#!/usr/bin/env bash
# Checks each release archive (//:zip_linux_<arch>): one entry,
# `bootstrap`, executable, and an ELF executable of the architecture the
# archive is named for, with no program interpreter, so static. The arguments
# are linux_<arch>=<path>.
set -euo pipefail

# u <file> <offset> <bytes>: the little-endian unsigned integer there.
u() {
	od -An -tu"$3" -j"$2" -N"$3" "$1" | tr -d ' \n'
}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

check() { # name zip machine
	local name="$1" zip="$2" machine="$3" dir phoff phentsize phnum i
	dir="$(mktemp -d)"
	trap 'rm -rf "${dir}"' RETURN
	[ "$(unzip -Z1 "${zip}")" = bootstrap ] || fail "${name}: the archive does not hold exactly bootstrap"
	unzip -q "${zip}" -d "${dir}"
	[ -x "${dir}/bootstrap" ] || fail "${name}: bootstrap is not executable"
	[ "$(od -An -tx1 -N5 "${dir}/bootstrap" | tr -d ' \n')" = 7f454c4602 ] || fail "${name}: not a 64-bit ELF file"
	[ "$(u "${dir}/bootstrap" 16 2)" = 2 ] || fail "${name}: not an executable (ET_EXEC)"
	[ "$(u "${dir}/bootstrap" 18 2)" = "${machine}" ] || fail "${name}: machine $(u "${dir}/bootstrap" 18 2), want ${machine}"
	phoff="$(u "${dir}/bootstrap" 32 8)"
	phentsize="$(u "${dir}/bootstrap" 54 2)"
	phnum="$(u "${dir}/bootstrap" 56 2)"
	for ((i = 0; i < phnum; i++)); do
		# PT_INTERP: a dynamically linked executable names its loader.
		[ "$(u "${dir}/bootstrap" $((phoff + i * phentsize)) 4)" != 3 ] || fail "${name}: has a program interpreter, so it is not static"
	done
	echo "ok: ${name}"
}

for arg in "$@"; do
	name="${arg%%=*}"
	zip="${arg#*=}"
	case "${name}" in
	linux_amd64) check "${name}" "${zip}" 62 ;;
	linux_arm64) check "${name}" "${zip}" 183 ;;
	*) fail "unknown platform ${name}" ;;
	esac
done
