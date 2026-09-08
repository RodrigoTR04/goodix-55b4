#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build a DESTDIR stage of Plasma Login Manager with the fingerprint action.
# Does not install PAM files from upstream and does not write /usr.

set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pin=f1688d734227510068a4eab54e67b9528b5444d5
patch=$project_dir/integration/plasmalogin/fingerprint-login.patch

usage()
{
  echo "usage: $0 /path/to/plasma-login-manager STAGE_DIR" >&2
  exit 2
}

[ $# -eq 2 ] || usage
source_tree=$1
stage=$2

[ -d "$source_tree/.git" ] || { echo "plasma-login-manager must be a git checkout." >&2; exit 1; }
[ -f "$patch" ] || { echo "Missing $patch" >&2; exit 1; }
actual=$(git -C "$source_tree" rev-parse HEAD)
if [ "$actual" != "$pin" ]; then
  echo "plasma-login-manager must be checked out at $pin" >&2
  exit 1
fi

mkdir -p "$stage"
stage=$(CDPATH= cd -- "$stage" && pwd)
work_dir=$(mktemp -d /tmp/plasmalogin-build.XXXXXXXX)
checkout=$work_dir/src
build_dir=$work_dir/build

cleanup()
{
  git -C "$source_tree" worktree remove --force "$checkout" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

git -C "$source_tree" worktree add --detach "$checkout" "$pin" >/dev/null
git -C "$checkout" apply "$patch"
# Arch packages plasmalogin-helper and plasma-login-greeter in /usr/lib,
# not /usr/lib/libexec. Match that so the installer and the running daemon
# look in the same place.
cmake -S "$checkout" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_INSTALL_LIBEXECDIR=lib \
  -DKDE_INSTALL_LIBEXECDIR=lib \
  -DINSTALL_PAM_CONFIGURATION=OFF
cmake --build "$build_dir"
DESTDIR="$stage" cmake --install "$build_dir"

echo "Staged matching daemon, helper, and greeter under $stage"
echo "Install with: sudo $project_dir/tools/install-plasmalogin-fingerprint.sh install $stage"
