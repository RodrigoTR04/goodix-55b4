#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Local testing install for 27c6:55b4. Community PSK write is done by the
# driver on activation. This does not claim production readiness.
#
# Destinations follow FHS and the host layout. Override with environment
# variables when a distribution uses a different prefix.

set -eu
umask 077
# Do not inherit caller-controlled tool resolution in this privileged helper.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
prefix=${PREFIX:-/opt/libfprint-goodix-55b4}
udev_rules_dir=${UDEV_RULES_DIR:-/etc/udev/rules.d}
fprint_state_dir=${FPRINT_STATE_DIR:-/var/lib/fprint}
systemd_unit_dir=${SYSTEMD_UNIT_DIR:-/etc/systemd/system}
udev_src=$project_dir/data/udev/60-libfprint-goodix-55b4.rules
udev_dst=$destdir$udev_rules_dir/60-libfprint-goodix-55b4.rules
psk_dst=$destdir$fprint_state_dir/goodix-55b4.psk

usage()
{
  echo "usage: $0 --udev" >&2
  echo "       $0 --psk /path/to/goodix-55b4.psk" >&2
  echo "       $0 --libfprint /path/to/libfprint [--prefix DIR]" >&2
  echo "       $0 --uninstall [--prefix DIR]" >&2
  echo >&2
  echo "A private PSK is optional. Without --psk the overlay uses the public" >&2
  echo "community white-box and an all-zero TLS key. --libfprint also installs udev." >&2
  echo >&2
  echo "Optional environment: DESTDIR PREFIX UDEV_RULES_DIR FPRINT_STATE_DIR SYSTEMD_UNIT_DIR" >&2
  exit 2
}

rooted()
{
  printf '%s%s\n' "$destdir" "$1"
}

find_libfprint_libdir()
{
  install_root=$(rooted "$prefix")
  for candidate in \
      "$install_root/lib" \
      "$install_root/lib64" \
      "$install_root/lib/$(uname -m)-linux-gnu"
  do
    if [ -e "$candidate/libfprint-2.so" ] ||
       ls "$candidate"/libfprint-2.so* >/dev/null 2>&1; then
      printf '%s\n' "${candidate#"$destdir"}"
      return 0
    fi
  done
  printf '%s\n' "$prefix/lib"
}

if [ "$#" -lt 1 ]; then
  usage
fi

check_path()
{
  /usr/bin/python3 -I "$project_dir/tools/check-install-path.py" "$@"
}

# A root-run build executes build scripts: both this tree and the pinned
# libfprint input must be trusted before any build command is run.
[ "$(id -u)" -eq 0 ] || { echo "Run as root from a protected source tree." >&2; exit 1; }
check_path --tree "$project_dir"
for location in "$prefix" "$udev_rules_dir" "$fprint_state_dir" "$systemd_unit_dir"; do
  case "$location" in
    /*) ;;
    *) echo "Install paths must be absolute" >&2; exit 1 ;;
  esac
  check_path --missing "$(rooted "$location")"
done

install_udev()
{
  check_path --missing "$udev_dst"
  install -D -m 644 "$udev_src" "$udev_dst"
  if [ -z "$destdir" ] && command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules
    udevadm trigger --subsystem-match=usb --attr-match=idVendor=27c6 --attr-match=idProduct=55b4 || true
  fi
}

install_psk()
{
  src=$1
  check_path "$src"
  if [ "$(stat -c %s "$src")" != 32 ] || [ "$(stat -c %a "$src")" != 600 ]; then
    echo "PSK must be exactly 32 bytes with mode 0600" >&2
    exit 1
  fi
  check_path --missing "$psk_dst"
  if [ ! -f "$src" ]; then
    echo "PSK file is missing" >&2
    exit 1
  fi
  install -d -m 700 "$(rooted "$fprint_state_dir")"
  temporary=$(mktemp "$psk_dst.XXXXXXXX")
  trap 'rm -f "$temporary"' EXIT HUP INT TERM
  install -m 600 "$src" "$temporary"
  mv -fT "$temporary" "$psk_dst"
  trap - EXIT HUP INT TERM
}

install_libfprint()
{
  source_tree=$1
  check_path --missing "$(rooted "$prefix")"
  check_path --tree "$source_tree"
  service_user=$(systemctl show fprintd.service -p User --value)
  case "$service_user" in
    ''|root) ;;
    *) echo "This installer requires a root-running fprintd; use distribution packaging for another service account." >&2; exit 1 ;;
  esac
  work_dir=$(mktemp -d /var/tmp/goodix-build.XXXXXXXX)
  base_prefix=$prefix
  prefix=$base_prefix/releases/$(basename "$work_dir")
  check_path --missing "$(rooted "$prefix")"
  checkout=$work_dir/libfprint
  build_dir=$work_dir/build
  pin=6f9479c3d55f847c1b3769f28ceb99227f9858cf
  actual=$(git -C "$source_tree" rev-parse HEAD)
  if [ "$actual" != "$pin" ]; then
    echo "libfprint must be checked out at $pin" >&2
    exit 1
  fi
  cleanup()
  {
    git -C "$source_tree" worktree remove --force "$checkout" >/dev/null 2>&1 || true
    rm -rf "$work_dir"
  }
  trap cleanup EXIT HUP INT TERM
  git -C "$source_tree" worktree add --detach "$checkout" "$pin" >/dev/null
  mkdir -p "$checkout/libfprint/drivers/goodix55b4"
  cp "$project_dir/integration/libfprint/goodix55b4.c" "$project_dir"/src/goodix_*.[ch] \
    "$project_dir"/src/goodix_*.cpp "$checkout/libfprint/drivers/goodix55b4/"
  git -C "$checkout" apply "$project_dir/integration/libfprint/meson.patch"
  git -C "$checkout" apply "$project_dir/integration/libfprint/suspend-resume-removal.patch"
  meson setup "$build_dir" "$checkout" \
    --prefix="$prefix" \
    -Ddrivers=goodix55b4 \
    -Ddoc=false \
    -Dgtk-examples=false \
    -Dinstalled-tests=false \
    -Dintrospection=false \
    -Dudev_hwdb=disabled \
    -Dudev_rules=disabled \
    -Dc_args=-DGOODIX55B4_DEVELOPMENT=1 \
    -Dcpp_args=-DGOODIX55B4_DEVELOPMENT=1
  meson compile -C "$build_dir"
  # Publish a new, immutable-by-unprivileged-users release only after the
  # build and staged install succeed. The active service stays on its old one.
  meson install -C "$build_dir" --destdir="$work_dir/stage"
  install -d -m 755 "$(rooted "$base_prefix/releases")"
  [ ! -e "$(rooted "$prefix")" ] || exit 1
  mv "$work_dir/stage$prefix" "$(rooted "$prefix")"
  libdir=$(find_libfprint_libdir)
  # Use the ELF interpreter explicitly, keeping loader search out of the
  # daemon environment. This installer supports the root-running fprintd unit.
  daemon=
  for candidate in /usr/lib/fprintd /usr/libexec/fprintd; do
    if [ -x "$candidate" ]; then daemon=$candidate; break; fi
  done
  [ -n "$daemon" ] || { echo "fprintd executable not found" >&2; exit 1; }
  loader=$(readelf -l "$daemon" | sed -n 's/.*Requesting program interpreter: \(.*\)\]/\1/p')
  [ -n "$loader" ] || { echo "ELF loader not found" >&2; exit 1; }
  loader=$(realpath -e "$loader")
  daemon=$(realpath -e "$daemon")
  check_path "$loader" "$daemon"
  # Meson produces SONAME links. Validate their resolved targets and every
  # directory; the source validator deliberately forbids input symlinks.
  check_path "$(rooted "$libdir")"
  for library in "$(rooted "$libdir")"/libfprint-2.so*; do
    resolved=$(realpath -e "$library")
    case "$resolved" in "$(rooted "$libdir")"/*) ;; *) exit 1 ;; esac
    check_path "$resolved"
  done
  dropin=$(rooted "$systemd_unit_dir/fprintd.service.d/goodix55b4.conf")
  check_path --missing "$dropin"
  install -d -m 755 "$(dirname "$dropin")"
  temporary=$(mktemp "$dropin.XXXXXXXX")
  cat >"$temporary" <<EOF
[Service]
LimitCORE=0
ExecStart=
ExecStart=$loader --library-path $libdir $daemon
EOF
  chmod 644 "$temporary"
  mv -fT "$temporary" "$dropin"
  if [ -z "$destdir" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
}

uninstall()
{
  dropin=$(rooted "$systemd_unit_dir/fprintd.service.d/goodix55b4.conf")
  if [ -e "$udev_dst" ]; then
    check_path "$udev_dst"
    rm -f "$udev_dst"
    if [ -z "$destdir" ] && command -v udevadm >/dev/null 2>&1; then
      udevadm control --reload-rules
      udevadm trigger --subsystem-match=usb --attr-match=idVendor=27c6 --attr-match=idProduct=55b4 || true
    fi
  fi
  if [ -e "$dropin" ]; then
    check_path "$dropin"
    rm -f "$dropin"
    rmdir "$(dirname "$dropin")" 2>/dev/null || true
    if [ -z "$destdir" ] && command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload
    fi
  fi
}

case $1 in
  --udev)
    [ "$#" -eq 1 ] || usage
    install_udev
    ;;
  --psk)
    [ "$#" -eq 2 ] || usage
    install_psk "$2"
    ;;
  --libfprint)
    [ "$#" -eq 2 ] || [ "$#" -eq 4 ] || usage
    if [ "$#" -eq 4 ]; then
      [ "$3" = --prefix ] || usage
      prefix=$4
    fi
    install_udev
    install_libfprint "$2"
    ;;
  --uninstall)
    [ "$#" -eq 1 ] || [ "$#" -eq 3 ] || usage
    if [ "$#" -eq 3 ]; then
      [ "$2" = --prefix ] || usage
      prefix=$3
    fi
    uninstall
    ;;
  *)
    usage
    ;;
esac
