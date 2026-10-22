# AGENTS.md

Guidance for agents working in this repository.

## What this is

An AWS Lambda that implements AWS Secrets Manager rotation for an intermediate
CA signed by an AWS KMS key: it keeps a name-constrained intermediate in a
secret. It is generic, not tied to any consumer of the intermediate. The
repository is a public one: no account IDs, ARNs, key IDs, personal domains or
host names anywhere (code, tests, examples, docs, workflows). Examples use
`example.org`. No secrets.

The rotation code is not written yet; `cmd/rotator/main.go` is a stub that
prints its version.

## Build and test

```bash
bazel test //...                # builds and runs the unit tests
bazel run //:gazelle            # after adding, removing or renaming any .go file
bazel run //:format             # format Starlark, Go and shell; CI runs //:format.check
bazel mod tidy                  # after changing go.mod or a bazel_dep
bazel build --config=ci //...   # what CI builds: lockfile must be current, shellcheck and gocognit on
bazel run //cmd/rotator -- --version
```

Bazel is the only build. Never use the host `go` tool, and do not "fix" go.mod
with `go mod tidy`. Change a Go dependency through rules_go's SDK:

```bash
bazel run @rules_go//go -- get github.com/some/module@v1.2.3
```

Follow it with `bazel mod tidy` and `bazel run //:gazelle`. User-local Bazel
settings go in `user.bazelrc` (untracked); on a machine with `GOPROXY=direct`
it points module fetches at the public proxy.

Linting is part of the build. Every Go package is compiled with the analyzers
of `//:nogo` (`go vet`'s and staticcheck's), and a finding is a compile error:
fix it rather than excluding the file. Shell scripts are checked by shellcheck
and Go functions by gocognit, both aspects that `--config=ci` turns on; a
script is only seen through a Bazel target (`//bazel:scripts`). gocognit
(`bazel/lint/linters.bzl`) fails a function over 15 and visits production code
only; the threshold never goes up.

`bazel run //:format` formats Starlark (buildifier), Go (gofumpt) and shell
(shfmt, tabs). CI fails if it would change anything, or if Gazelle leaves a
diff.

## Layout

- `cmd/rotator`: the Lambda. The binary is named `bootstrap` (`basename`), as
  the `provided.al2023` runtime requires.
- `internal/version`: the build version, stamped from the git state.
- `pkg/...`: libraries (intermediate, kmssigner, rotation) arrive with the code.
- `bazel/`: build rules and CI scripts: `workspace_status.sh` (stamping),
  `ci-impacted-targets.sh` (bazel-diff), `nogo/`, `lint/`, `format/`,
  `platforms/`, `cosign/`.

## Release archives

`//cmd/rotator:zip_linux_arm64` and `//cmd/rotator:zip_linux_amd64` are
`pkg_zip`s of the binary cross-compiled for that platform (`go_cross_binary`,
pure Go, CGO off), holding one executable file `bootstrap`, mode 0755, with
fixed timestamps so the same inputs give the same bytes. The binary is stamped
with the release (`--version`). There is no container image.

`//cmd/rotator:release_zips_test` holds the contents of both archives
(one executable `bootstrap`, ELF of the right machine, static).

The archives' names in Bazel carry no version; `.github/workflows/release.yml`
copies them to `kms-intermediate-rotator_<version>_linux_<arch>.zip`. Keep its
`PLATFORMS` equal to the list in `cmd/rotator/BUILD.bazel`.

## Versions and releasing

`VERSION` is the release being worked towards. A commit tagged `v<VERSION>`
(or `v<VERSION>-rc.<n>`) is that release; any other commit is a snapshot of it
(`bazel/workspace_status.sh`). Pushing a `v*` tag on a commit of main runs
`release.yml`: it builds both archives, writes `checksums.txt`, signs it with
cosign (keyless, GitHub OIDC), generates an SBOM and creates the GitHub
Release. Do not push tags by hand unless releasing.

## CI

`.github/workflows/ci.yml`: `lint` (format check, Gazelle staleness) always
runs; `diff` computes the impacted targets with bazel-diff
(`bazel/ci-impacted-targets.sh`) and `build` builds and tests only those. A
change to anything outside the graph that CI depends on (`.bazelrc`,
`MODULE.bazel`, the lint `.bzl` files, the workflow, the script) must be in the
script's seed list, or CI would skip the build. `ci` is the aggregate check to
require. Actions are pinned to commit SHAs with the version in a comment.

## Pull requests

One topic per pull request. Verify with `bazel build --config=ci //... &&
bazel test //...` before pushing.
