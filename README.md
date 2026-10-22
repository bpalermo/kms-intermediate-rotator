# kms-intermediate-rotator

AWS Secrets Manager rotation Lambda that keeps a name-constrained intermediate
CA, signed by an AWS KMS key, in a secret.

The root CA's private key stays in KMS. On each rotation the Lambda generates
a new intermediate key, builds the intermediate certificate from its own
configuration, has KMS sign it, and stores certificate, key and root in the
secret in the [secret format v1](docs/secret-format.md). Whatever consumes the
intermediate reads the secret's `AWSCURRENT` version; the rotator knows
nothing about it.

The Lambda (`cmd/rotator`) runs on the `provided.al2023` custom runtime, arm64
or x86_64.

## Rotation flow

Secrets Manager invokes the function four times per rotation, with
`{"SecretId", "ClientRequestToken", "Step"}` (an optional `RotationToken` is
accepted and ignored). Before every step, as the AWS rotation templates do,
the function checks that the secret is in its configuration (by full ARN; a
`SecretId` given as a name is resolved with `DescribeSecret`), that rotation
is enabled on it and that the token is one of its versions. If that version
is already `AWSCURRENT` the step succeeds and does nothing; if it is not
`AWSPENDING` the step fails.

1. **createSecret**: if the `AWSPENDING` version of the token already has a
   value (a retry), it returns without signing again. Otherwise it generates
   a key, builds the certificate from the secret's configuration, signs it
   with KMS (`Sign`, `MessageType: DIGEST`), checks the signature against the
   root, and writes the secret with `PutSecretValue` (the token,
   `VersionStages: [AWSPENDING]`).
2. **setSecret**: nothing; there is no service to configure.
3. **testSecret**: reads `AWSPENDING` and checks it as a reader would (format
   v1, key matches cert, cert verifies to the root), that its root is the
   configured one, that subject, basic constraints, path length, key usage,
   name constraints and key type equal the configuration, and that it is
   valid until at least now + `validity` − 24h.
4. **finishSecret**: moves `AWSCURRENT` to the token with
   `UpdateSecretVersionStage`, removing it from the version that had it
   (Secrets Manager then labels that one `AWSPREVIOUS`).

At cold start, before serving anything, the function loads its configuration
and calls KMS `GetPublicKey`: if the key's public key is not the configured
root certificate's, it refuses to start.

## The certificate

Nothing in it comes from the event; everything comes from the configuration:

- the configured subject; a random positive 128-bit serial number;
- `NotBefore` = now − 5m, `NotAfter` = now + `validity`, never after the
  root's `NotAfter`;
- basic constraints `CA:TRUE` with the configured path length (0 included),
  critical; key usage `keyCertSign | cRLSign`, critical;
- name constraints, critical, when any are configured: permitted and
  excluded URI domains and DNS domains, with the semantics of Go's
  `crypto/x509` (`example.org` matches that host, `.example.org` the hosts
  below it);
- subject key identifier = SHA-1 of the new public key (RFC 5280 method 1);
  authority key identifier = the root's subject key identifier.

Because testSecret wants the full validity minus a day, rotation starts to
fail once the root has less than `validity` − 24h left: the current
intermediate stays in place and keeps working until it expires. Alarm on
rotation failures and renew the root before then.

## Configuration

Exactly one of these environment variables must be set:

| Variable | Value |
| --- | --- |
| `ROTATOR_CONFIG` | the configuration, inline JSON |
| `ROTATOR_CONFIG_PARAMETER` | the name of an SSM parameter (`String` or `SecureString`) holding it, read once per cold start |

```json
{
  "kms_key_id": "alias/example-root",
  "root_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "signing_algorithm": "",
  "secrets": {
    "arn:aws:secretsmanager:us-east-1:111122223333:secret:example-AbCdEf": {
      "subject": {"common_name": "Example Intermediate CA", "organization": ["Example"], "country": ["US"]},
      "key_type": "ec-p256",
      "validity": "2160h",
      "max_path_len": 1,
      "name_constraints": {
        "permitted_uri_domains": ["example.org"],
        "excluded_uri_domains": [],
        "permitted_dns_domains": [".example.org"],
        "excluded_dns_domains": []
      }
    }
  }
}
```

| Field | Meaning | Default |
| --- | --- | --- |
| `kms_key_id` | the root's KMS key: key ID, key ARN, alias name or alias ARN; an asymmetric `SIGN_VERIFY` key | required |
| `root_certificate` | the root certificate, PEM, exactly one; its public key must be the KMS key's | required |
| `signing_algorithm` | a KMS signing algorithm (`ECDSA_SHA_256`, `ECDSA_SHA_384`, `ECDSA_SHA_512`, `RSASSA_PKCS1_V1_5_SHA_*`, `RSASSA_PSS_SHA_*`) | from the key spec: `ECC_NIST_P256` → `ECDSA_SHA_256`, `ECC_NIST_P384` → `ECDSA_SHA_384`, `ECC_NIST_P521` → `ECDSA_SHA_512`, `RSA_*` → `RSASSA_PKCS1_V1_5_SHA_256` |
| `secrets` | per secret, by ARN: what to issue. Use the full ARN (with the six random characters Secrets Manager appends) or the ARN without them. An event for any other secret fails. | at least one |
| `subject` | `common_name` (required), `organization`, `organizational_unit`, `country`, `province`, `locality` | |
| `key_type` | the intermediate's key: `ec-p256`, `ec-p384`, `rsa-2048`, `rsa-4096` | `ec-p256` |
| `validity` | a Go duration (`h`, `m`, `s`), positive | `2160h` (90 days) |
| `max_path_len` | path length constraint, 0 or more | `1` |
| `name_constraints` | `permitted_uri_domains`, `excluded_uri_domains`, `permitted_dns_domains`, `excluded_dns_domains` | none |

Unknown fields are errors, so a misspelt setting does not go unnoticed.

## IAM

The Lambda's execution role needs:

| Actions | Resource |
| --- | --- |
| `kms:GetPublicKey`, `kms:Sign` | the root KMS key (by key ARN; IAM does not match aliases) |
| `secretsmanager:DescribeSecret`, `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue`, `secretsmanager:UpdateSecretVersionStage` | the rotated secrets |
| `kms:Decrypt`, `kms:GenerateDataKey` (Encrypt) | the KMS key the secrets are encrypted with, when it is a customer managed key |
| `ssm:GetParameter` | the configuration parameter, with `ROTATOR_CONFIG_PARAMETER` only |
| `kms:Decrypt` | the parameter's key, for a `SecureString` with a customer managed key |
| `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` | its log group (`AWSLambdaBasicExecutionRole`) |

Secrets Manager must be allowed to invoke the function (a resource policy for
`secretsmanager.amazonaws.com`). The function calls KMS, Secrets Manager and,
with the parameter form, SSM: in a VPC it needs endpoints or a route to them.

## Deployment

A minimal Terraform example, with placeholder ARNs:

```hcl
locals {
  root_key_arn = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
  secret_cmk   = "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-111111111111"
}

resource "aws_secretsmanager_secret" "intermediate" {
  name       = "example-intermediate-ca"
  kms_key_id = local.secret_cmk
}

# A placeholder first version: the first rotation replaces it.
resource "aws_secretsmanager_secret_version" "placeholder" {
  secret_id     = aws_secretsmanager_secret.intermediate.id
  secret_string = "{}"
  lifecycle { ignore_changes = [secret_string] }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "rotator" {
  statement {
    actions   = ["kms:GetPublicKey", "kms:Sign"]
    resources = [local.root_key_arn]
  }
  statement {
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage",
    ]
    resources = [aws_secretsmanager_secret.intermediate.arn]
  }
  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [local.secret_cmk]
  }
}

resource "aws_iam_role" "rotator" {
  name               = "kms-intermediate-rotator"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "rotator" {
  role   = aws_iam_role.rotator.id
  policy = data.aws_iam_policy_document.rotator.json
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.rotator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "rotator" {
  function_name = "kms-intermediate-rotator"
  role          = aws_iam_role.rotator.arn
  runtime       = "provided.al2023"
  architectures = ["arm64"]
  handler       = "bootstrap"
  # From the GitHub Release; verify checksums.txt first (see Releases).
  filename         = "kms-intermediate-rotator_0.1.0_linux_arm64.zip"
  source_code_hash = filebase64sha256("kms-intermediate-rotator_0.1.0_linux_arm64.zip")
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ROTATOR_CONFIG = jsonencode({
        kms_key_id       = local.root_key_arn
        root_certificate = file("root.pem")
        secrets = {
          (aws_secretsmanager_secret.intermediate.arn) = {
            subject      = { common_name = "Example Intermediate CA", organization = ["Example"] }
            validity     = "2160h"
            max_path_len = 0
            name_constraints = {
              permitted_uri_domains = ["example.org"]
              permitted_dns_domains = [".example.org"]
            }
          }
        }
      })
    }
  }
}

resource "aws_lambda_permission" "secretsmanager" {
  statement_id   = "AllowSecretsManager"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.rotator.function_name
  principal      = "secretsmanager.amazonaws.com"
  source_account = "111122223333"
}

resource "aws_secretsmanager_secret_rotation" "intermediate" {
  secret_id           = aws_secretsmanager_secret.intermediate.id
  rotation_lambda_arn = aws_lambda_function.rotator.arn
  rotation_rules {
    # Well inside the 90-day validity, so a failed rotation has time to be
    # noticed before the current intermediate expires.
    schedule_expression = "rate(30 days)"
  }
  depends_on = [aws_lambda_permission.secretsmanager, aws_secretsmanager_secret_version.placeholder]
}
```

## Logs

One JSON object per line on stdout (`log/slog`). Each issued certificate is
logged once, with `secret_arn`, `serial` (hex), `not_after` (RFC 3339) and
`public_key_sha256` (SHA-256 of the SubjectPublicKeyInfo DER). No private key
or certificate is ever logged.

## Releases

A release attaches, to its GitHub Release:

- `kms-intermediate-rotator_<version>_linux_arm64.zip` and
  `kms-intermediate-rotator_<version>_linux_amd64.zip`, each holding one
  statically linked executable, `bootstrap`;
- `checksums.txt` (SHA-256), signed keyless with cosign
  (`checksums.txt.sigstore.json`);
- an SBOM (`kms-intermediate-rotator_<version>_sbom.spdx.json`).

Verify a download:

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity 'https://github.com/bpalermo/kms-intermediate-rotator/.github/workflows/release.yml@refs/tags/v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

## Build

Bazel is the only build; the version is pinned in `.bazelversion` and Bazelisk
picks it up.

```bash
bazel build //cmd/rotator:zip_linux_arm64 //cmd/rotator:zip_linux_amd64   # the archives
bazel build //cmd/rotator                                                 # the binary, for this host
bazel test //...
bazel run //cmd/rotator -- --version
```

The archives are in `bazel-bin/cmd/rotator/`. The tests use in-process fakes
of KMS and Secrets Manager backed by real keys; they make no network calls.
See [AGENTS.md](AGENTS.md) for the layout and the rest of the commands.

## License

Apache-2.0, see [LICENSE](LICENSE).
