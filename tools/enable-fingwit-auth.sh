#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Unblock Fingwit's management page on Arch and CachyOS. Fingwit's Enable
# button runs Debian pam-auth-update, which is not present here.
#
# This does not enable fingerprint login. Putting pam_fprintd in system-auth
# or plasmalogin serializes a reader timeout in front of every password prompt
# (sudo, login, and the greeter). Use integration/plasmalogin for an explicit
# login-screen fingerprint action, and keep KDE screen unlock on kde-fingerprint.

set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

fingwit_pam=/usr/lib/security/pam_fingwit.so
common_auth=/etc/pam.d/common-auth
system_auth=/etc/pam.d/system-auth

if [ -f "$system_auth" ] && grep -q 'pam_fprintd\.so' "$system_auth"; then
  echo "Warning: $system_auth already contains pam_fprintd." >&2
  echo "That delays password login and sudo. Restore the .bak.* copy if this" >&2
  echo "helper previously inserted it." >&2
fi

if [ -f "$fingwit_pam" ]; then
  cat >"$common_auth" <<'EOF'
#%PAM-1.0
# Fingwit only treats fingerprint management as enabled when this
# Debian-style file contains pam_fingwit.so. Arch login and sudo use
# system-auth, which this file does not change.
auth [success=1 default=ignore] pam_fingwit.so
auth sufficient pam_fprintd.so max-tries=1 timeout=15
EOF
  chmod 644 "$common_auth"
  echo "Wrote $common_auth so Fingwit can leave the disabled page"
  echo "Fingerprint login is not enabled. See integration/plasmalogin/README.md"
else
  echo "pam_fingwit.so is missing; Fingwit may still show disabled." >&2
  echo "Enrollment still works through fprintd. Login is separate:" >&2
  echo "see integration/plasmalogin/README.md" >&2
  exit 1
fi
