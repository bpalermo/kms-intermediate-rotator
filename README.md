# kms-intermediate-rotator

AWS Secrets Manager rotation Lambda that keeps a name-constrained intermediate
CA, signed by an AWS KMS key, in a secret.

The Lambda (`cmd/rotator`) runs on the `provided.al2023` custom runtime. It is
generic: it knows nothing about what consumes the intermediate. This
repository is the skeleton; the rotation itself is still to come.

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

The archives are in `bazel-bin/cmd/rotator/`. See [AGENTS.md](AGENTS.md) for
the layout and the rest of the commands.

## License

Apache-2.0, see [LICENSE](LICENSE).
