# Secret format (`intermediate-ca/v1`)

The secret this rotator writes is in the `intermediate-ca/v1` format, which is
specified, with its protobuf schema and its conformance test documents, in
[bpalermo/intermediate-ca-format](https://github.com/bpalermo/intermediate-ca-format):
see its
[docs/secret-format.md](https://github.com/bpalermo/intermediate-ca-format/blob/11d2a916960bad46d75ce9e7fcbc999dbf9b069c/docs/secret-format.md)
(at the commit `go.mod` pins). That document is the contract with the
secret's readers; nothing here changes it.

The rotator uses that module's Go package (`intermediateca`) to write the
secret (`Encode`) and, as any reader does, to check it (`DecodeAt`): before a
new version is stored, and again in testSecret. Its version is the one in
`go.mod`.

## What this rotator writes

Informative, not part of the contract:

- `cert` is issued directly by the root, so `chain` is always `""`.
- `root` is the configured `root_certificate`, re-encoded from its DER.
- `key` is a newly generated key of the configured `key_type`, as an
  unencrypted PKCS#8 `PRIVATE KEY` block. The key exists only in the Lambda's
  memory and in the secret.
- The JSON is what `intermediateca.Encode` writes: compact, with exactly the
  five fields, in the order `format`, `cert`, `key`, `chain`, `root`.

## What testSecret checks beyond the format

A pending version a reader would accept can still be refused by testSecret,
which also requires that:

- its `root` is the configured root certificate;
- its `cert` is what createSecret issues from the secret's configuration
  (subject, key type, basic constraints and path length, key usage, name
  constraints, with their criticality);
- a chain as deep as the `cert`'s path length allows verifies to the root;
- its lifetime is the configured `validity` (or up to the root's expiry), and
  at least `min_remaining` of it is left.
