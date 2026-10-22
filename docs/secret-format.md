# Secret format v1 (`intermediate-ca/v1`)

This is the contract between this rotator, which writes the secret, and its
readers (such as a SPIRE UpstreamAuthority plugin kept in a separate
repository). They share no code; this document is the agreement. The section
below is normative and is kept word for word in step with the readers' copy.

## Format

`SecretString` is JSON:

```json
{
  "format": "intermediate-ca/v1",
  "cert":  "-----BEGIN CERTIFICATE-----\n...",      // the intermediate CA, PEM, exactly one cert
  "key":   "-----BEGIN PRIVATE KEY-----\n...",      // its private key, PKCS#8 PEM
  "chain": "",                                       // PEM certs between cert and root, may be empty
  "root":  "-----BEGIN CERTIFICATE-----\n..."       // the trust anchor, PEM, exactly one cert
}
```

Readers MUST reject an unknown `format`, a `cert` whose public key does not match `key`, and
a `cert` that does not verify to `root` through `chain`. Unknown extra fields are ignored.


## What this rotator writes

Informative, not part of the contract:

- `cert` is issued directly by the root, so `chain` is always `""`.
- `root` is the configured `root_certificate`, re-encoded from its DER.
- `key` is a newly generated key of the configured `key_type`, as an
  unencrypted PKCS#8 `PRIVATE KEY` block. The key exists only in the Lambda's
  memory and in the secret.
- The JSON has exactly the five fields above. `pkg/secretformat` is the
  implementation (`Decode` is what a reader must do: parse, then reject a key
  that does not match and a cert that does not verify).
