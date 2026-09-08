#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Install the explicit Plasma Login Manager fingerprint action. This replaces
# the daemon, helper, and greeter binaries and adds plasmalogin-fingerprint.
# It does not modify the plasmalogin password PAM service.

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly STATE_DIR=/var/lib/goodix-plasmalogin
readonly PAM_TARGET=/etc/pam.d/plasmalogin-fingerprint
readonly PAM_MODULE=/usr/lib/security/pam_fprintd.so
readonly TARGETS=(
    /usr/bin/plasmalogin
    /usr/lib/plasmalogin-helper
    /usr/lib/plasma-login-greeter
)

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pam_source=$project_dir/integration/plasmalogin/plasmalogin-fingerprint.pam

usage() {
    echo "Usage: $0 install STAGE_DIR | rollback [BACKUP_DIR] | status" >&2
    exit 2
}

[[ ${EUID} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

case "${1:-}" in
install)
    [[ $# -eq 2 ]] || usage
    stage=${2%/}
    sources=(
        "$stage/usr/bin/plasmalogin"
        "$stage/usr/lib/plasmalogin-helper"
        "$stage/usr/lib/plasma-login-greeter"
    )
    for source in "${sources[@]}"; do
        [[ -x $source ]] || { echo "Missing staged executable: $source" >&2; exit 1; }
    done
    [[ -f $pam_source ]] || {
        echo "Missing $pam_source. Run this command from a complete checkout." >&2
        exit 1
    }
    [[ -f $PAM_MODULE ]] || {
        echo "pam_fprintd.so is missing; install fprintd before fingerprint login." >&2
        exit 1
    }
    if [[ -e /etc/pam.d/plasmalogin ]] && grep -q 'pam_fprintd\.so' /etc/pam.d/plasmalogin; then
        echo "Refusing to install while /etc/pam.d/plasmalogin contains pam_fprintd." >&2
        echo "Restore the password service first so login is not serialized." >&2
        exit 1
    fi
    install -d -m 0700 "$STATE_DIR"
    backup="$STATE_DIR/backup-$(date -u +%Y%m%dT%H%M%SZ)"
    install -d -m 0700 "$backup"
    for target in "${TARGETS[@]}"; do
        install -m 0755 "$target" "$backup/$(basename "$target")"
    done
    if [[ -e $PAM_TARGET ]]; then
        install -m 0644 "$PAM_TARGET" "$backup/plasmalogin-fingerprint.pam"
        : > "$backup/pam-existed"
    fi
    for index in "${!TARGETS[@]}"; do
        install -m 0755 "${sources[$index]}" "${TARGETS[$index]}"
    done
    install -m 0644 "$pam_source" "$PAM_TARGET"
    printf '%s\n' "$backup" > "$STATE_DIR/current-backup"
    echo "Installed. Reboot to load the matching daemon, helper, and greeter."
    echo "Rollback: $0 rollback $backup"
    ;;
rollback)
    [[ $# -le 2 ]] || usage
    backup=${2:-}
    if [[ -z $backup ]]; then
        [[ -f $STATE_DIR/current-backup ]] || { echo "No recorded backup." >&2; exit 1; }
        read -r backup < "$STATE_DIR/current-backup"
    fi
    [[ -d $backup && $backup == "$STATE_DIR"/backup-* ]] || { echo "Invalid backup: $backup" >&2; exit 1; }
    for target in "${TARGETS[@]}"; do
        source="$backup/$(basename "$target")"
        [[ -f $source ]] || { echo "Incomplete backup: $source" >&2; exit 1; }
        install -m 0755 "$source" "$target"
    done
    if [[ -f $backup/pam-existed ]]; then
        install -m 0644 "$backup/plasmalogin-fingerprint.pam" "$PAM_TARGET"
    else
        [[ ! -e $PAM_TARGET ]] || unlink "$PAM_TARGET"
    fi
    echo "Restored $backup. Reboot to load the restored login manager."
    ;;
status)
    sha256sum "${TARGETS[@]}" 2>/dev/null || true
    if [[ -f $STATE_DIR/current-backup ]]; then
        echo -n "Backup: "
        cat "$STATE_DIR/current-backup"
    fi
    [[ -f $PAM_TARGET ]] && echo "Fingerprint PAM service: installed" || echo "Fingerprint PAM service: absent"
    ;;
*) usage ;;
esac
