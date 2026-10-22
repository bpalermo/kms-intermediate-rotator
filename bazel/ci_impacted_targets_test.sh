#!/usr/bin/env bash
# The decision of ci-impacted-targets.sh after bazel-diff: `classify` turns
# an impacted list and the two candidate lists into impacted_build.txt,
# impacted_test.txt and the flags has_any and has_test. Fed with fixture
# lists, so the logic is covered without bazel-diff or Bazel.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/ci-impacted-targets.sh"
[ -r "${script}" ] || script="${TEST_SRCDIR}/_main/bazel/ci-impacted-targets.sh"
# The script is linted on its own, through //bazel:scripts.
# shellcheck source=/dev/null
source "${script}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# The candidate lists, as the queries would answer them: the buildable rules
# (sorted, no `manual` rule, so no //:gazelle) and the tests `bazel test //...` runs.
cat >"${work}/rules.txt" <<'LIST'
//:rotator
//:rotator_linux_arm64
//:kms-intermediate-rotator_test
//:zip_linux_arm64
//internal/version:version
//internal/version:version_test
LIST
cat >"${work}/tests.txt" <<'LIST'
//:kms-intermediate-rotator_test
//internal/version:version_test
LIST

fail=0
# expect <case> <impacted lines> <want build> <want test>: runs classify over
# the fixture lists and compares the two lists and the flags. The lists are
# given one label per line, as bazel-diff sorts them.
expect() {
	local name="$1" impacted="$2" want_build="$3" want_test="$4"
	local out="${work}/${name}" want_any want_has_test
	mkdir -p "${out}"
	printf '%s' "${impacted}" >"${out}/impacted.txt"
	has_any='' has_test=''
	if ! classify "${out}/impacted.txt" "${work}/rules.txt" "${work}/tests.txt" "${out}"; then
		echo "FAIL: ${name}: classify failed" >&2
		fail=1
		return
	fi
	check_list "${name}" impacted_build.txt "${out}" "${want_build}"
	check_list "${name}" impacted_test.txt "${out}" "${want_test}"
	want_any=false
	[ -n "${want_build}" ] && want_any=true
	want_has_test=false
	[ -n "${want_test}" ] && want_has_test=true
	check_flag "${name}" has_any "${has_any}" "${want_any}"
	check_flag "${name}" has_test "${has_test}" "${want_has_test}"
}
check_list() { # case file dir want
	local got
	got="$(cat "$3/$2")"
	if [ "${got}" != "$4" ]; then
		echo "FAIL: $1: $2 is:" >&2
		sed 's/^/    /' "$3/$2" >&2
		echo "  want:" >&2
		printf '%s\n' "$4" | sed 's/^/    /' >&2
		fail=1
	fi
}
check_flag() { # case name got want
	if [ "$3" != "$4" ]; then
		echo "FAIL: $1: $2 is '$3', want '$4'" >&2
		fail=1
	fi
}

# Nothing impacted (a documentation-only change): both lists empty, both
# flags false, and it is the classification saying so, not a failure.
expect nothing "" "" ""

# A change to the root package: its library, binary, test and the zips built
# from it. Source-file labels (//:main.go) and a `manual` rule
# (//:gazelle) are in no candidate list and are dropped.
expect rotator "//:gazelle
//:main.go
//:rotator
//:rotator_linux_arm64
//:kms-intermediate-rotator_test
//:zip_linux_arm64
" "//:rotator
//:rotator_linux_arm64
//:kms-intermediate-rotator_test
//:zip_linux_arm64" "//:kms-intermediate-rotator_test"

# A library with a test: built and tested.
expect library "//internal/version:version
//internal/version:version_test
" "//internal/version:version
//internal/version:version_test" "//internal/version:version_test"

# Labels in no candidate list (an external target, a removed-looking label):
# nothing to build, and still a classification.
expect foreign "@rules_go//go:def.bzl
//gone:gone
" "" ""

# An impacted target is matched whole: //:rotator is not matched
# by the prefix of //:rotator_linux_arm64, which it begins.
expect whole "//:rotator
" "//:rotator" ""

# classify fails, rather than answering, when a candidate list is unreadable.
if classify "${work}/rotator/impacted.txt" "${work}/missing.txt" "${work}/tests.txt" "${work}/rotator" 2>/dev/null; then
	echo "FAIL: classify succeeded with a missing candidate list" >&2
	fail=1
fi

[ "${fail}" -eq 0 ] || exit 1
echo PASS
