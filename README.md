# Goodix 27c6:55b4 support for libfprint

Linux support for the Goodix USB fingerprint reader with USB ID `27c6:55b4`:
a libfprint driver overlay, a USB probe, and an install script.

**Experimental.** Enroll, Verify, Identify and Capture are compiled out unless
the driver is built with `-DGOODIX55B4_DEVELOPMENT=1` (raster Capture also
needs `-DGOODIX55B4_DEVELOPMENT_CAPTURE=1`). The SIGFM matcher has not been
qualified for a false-accept rate. Do not treat fingerprint PAM as equivalent
to a password.

Rasters are not stored. Enrollment keeps only SIGFM features, sealed with
AES-256-GCM under a 0600 wrap key at `/var/lib/fprint/goodix-55b4.wrap` (or
`GOODIX55B4_WRAP_FILE`). Plaintext templates are rejected. USB frames still
use TLS in transit and are wiped after extraction. The wrap key sits on the
same disk as the templates, so `fprintd` or a stolen disk that includes that
file can unwrap them. Full-disk encryption is the Linux-native way to cover
that case. This driver does not use the TPM or Secure Boot.

## Build

Install Meson, Ninja, C and C++ compilers, and the libusb, OpenSSL, and OpenCV
development packages. On Debian or Ubuntu, libusb and OpenSSL are named
`libusb-1.0-0-dev` and `libssl-dev`. OpenSSL must provide
`SSL_OP_CLEANSE_PLAINTEXT`. SIGFM uses OpenCV 4 or 5 and is built when one is
available; require it with `-Dsigfm=enabled`.

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

After changing build options or pulling new changes, run
`meson setup --reconfigure build`.

## Install

These steps do not write firmware. Run them as root only for udev and the
optional fprintd overlay. The installer requires a reviewed, root-owned copy of
both source trees and protected root-owned ancestors; it rejects a normal
user-owned checkout. It also requires Python 3 and binutils. The overlay
installer supports only a root-running fprintd service. The udev rule sets mode
`0600` and does not grant seat-user USB access; `fprintd` can still open the
device. Use `sudo` for the probe.

Run the installer from a **root-owned** copy of this repository (not from
`tools/`, and not from a home-directory checkout). `--libfprint` must be a
libfprint git checkout at `6f9479c3d55f847c1b3769f28ceb99227f9858cf`. Both
trees must be owned by root with no group/other write bits.

```sh
# Copy this checkout, including uncommitted work, then clone libfprint.
sudo rsync -a --delete ./ /root/goodix-55b4/
sudo chown -R root:root /root/goodix-55b4
sudo chmod -R go-w /root/goodix-55b4
sudo git clone https://gitlab.freedesktop.org/libfprint/libfprint.git /root/libfprint
sudo git -C /root/libfprint checkout --detach 6f9479c3d55f847c1b3769f28ceb99227f9858cf
sudo /root/goodix-55b4/tools/install-local.sh --libfprint /root/libfprint
```

That installs udev rules and the overlay. Uninstall the drop-in and udev rule
with `sudo ./tools/install-local.sh --uninstall`. The overlay is installed into
a new release directory beneath `/opt/libfprint-goodix-55b4` (`PREFIX` or
`--prefix` to change it). An atomic systemd drop-in selects it through the
system ELF loader's `--library-path` and sets `LimitCORE=0`. Review the drop-in
before restarting fprintd.

No host-specific pairing key is required. On activation the driver reads the
device PMK hash. If it does not match the public community hash, it writes the
community white-box (`0xe0`). TLS then uses 32 zero bytes. That write replaces
a Windows pairing until Windows boots again and reprovisions its own key.

A private 32-byte file is still optional if you want to keep a Windows pairing
without writing the community key:

```sh
sudo ./tools/install-local.sh --psk /path/to/goodix-55b4.psk
```

The driver looks for that file in this order:
`GOODIX55B4_PSK_FILE`, `$XDG_STATE_HOME/libfprint-goodix-55b4/goodix-55b4.psk`
(or `~/.local/state/...` when `XDG_STATE_HOME` is unset), then
`/var/lib/fprint/goodix-55b4.psk`. If none of those files are accepted, the
community TLS key is used. Remove a leftover private file if you want the
community path. A private file must remain mode 0600 and owned by the process
that opens the reader (`fprintd` after the overlay install). Keep any private
key outside this repository.

Development enrollment uses SIGFM format version 2; older SIGFM and NBIS
templates are rejected and require deletion and re-enrollment.

The overlay installer compiles enroll, verify, and identify in so Fingwit can
enroll. The SIGFM matcher is still unqualified; treat login unlock as
experimental.

## Fingwit on Arch / CachyOS

Fingwit’s Enable button runs `pam-auth-update`, which Debian provides and Arch-based
systems do not, so the button does nothing. After the overlay is installed,
unblock management from a root-owned copy of this tree. That helper writes a
Debian-style `common-auth` file so Fingwit leaves the disabled page. It does
**not** put `pam_fprintd` in `system-auth` or `plasmalogin`: Linux-PAM would
then wait for a fingerprint timeout before accepting a password, including on
cold boot and sudo.

```sh
sudo rsync -a --delete ./ /root/goodix-55b4/
sudo chown -R root:root /root/goodix-55b4
sudo chmod -R go-w /root/goodix-55b4
sudo /root/goodix-55b4/tools/install-local.sh --libfprint /root/libfprint
sudo /root/goodix-55b4/tools/enable-fingwit-auth.sh
sudo systemctl restart fprintd
```

Reopen Fingwit. It should leave the disabled page. Then enroll a finger in the
app.

Only one client may Claim the reader. Close Fingwit before opening KDE Plasma
Users → Fingerprints (or `fprintd-enroll`). If Fingwit stays open, Plasma
reports that the device is already claimed or in use by another user. Do not
use the `fingerprint-gui` package; it is a separate stack and will not see
prints enrolled through fprintd.

This libfprint pin treated Verify as an invalid image-device action, so PAM
and Plasma never recognized a print even after a successful enroll. The
overlay patch allows Verify. After updating this tree, rsync again, rerun
the installer, restart fprintd, delete old prints if they were stored before
the seal format, and enroll again.

## Plasma Login Manager fingerprint (cold boot)

KDE screen unlock already uses a separate `kde-fingerprint` PAM service, so
the lock screen can offer fingerprint without delaying password unlock. Plasma
Login Manager 6.7.3 has no equivalent until this overlay is installed.

Password submissions stay on the stock `plasmalogin` service. Fingerprint
login is a greeter button that starts the helper with `plasmalogin-fingerprint`
only after a user is selected. Wait for the PAM prompt before touching the
reader so a resting finger is not part of the absent-finger background. The
SIGFM matcher is still unqualified; treat this as experimental.

```sh
sudo git clone https://invent.kde.org/plasma/plasma-login-manager.git /root/plasma-login-manager
sudo git -C /root/plasma-login-manager checkout --detach f1688d734227510068a4eab54e67b9528b5444d5
sudo /root/goodix-55b4/tools/build-plasmalogin-fingerprint.sh \
    /root/plasma-login-manager /root/plasmalogin-fingerprint-stage
sudo /root/goodix-55b4/tools/install-plasmalogin-fingerprint.sh \
    install /root/plasmalogin-fingerprint-stage
```

Reboot so a cold greeter loads the matching daemon, helper, and greeter.
See [`integration/plasmalogin/README.md`](integration/plasmalogin/README.md).

## Probe and optional pairing recovery

`goodix-probe` uses libusb. It does not upload firmware, access flash, enroll a
fingerprint, or write image files. Stop `fprintd` only for the duration of the
probe if it already owns the device.

```sh
sudo ./build/goodix-probe --firmware
sudo ./build/goodix-probe --iap-version
sudo ./build/goodix-probe --psk-status
```

`--psk-status` reports whether the device already has the community PMK hash.
To recover a DPAPI-sealed pairing blob from the reader, use an absolute output
path outside the repository:

```sh
sudo ./build/goodix-probe \
  --read-sealed-psk /path/to/goodix-55b4-sealed.bin
```

Unseal it on the Windows installation that paired the reader:

```powershell
.\tools\windows\goodix_unseal.ps1 `
    -SealedBlob $env:LOCALAPPDATA\libfprint-goodix-55b4\goodix-55b4-sealed.bin `
    -OutPsk $env:LOCALAPPDATA\libfprint-goodix-55b4\goodix-55b4.psk
```

The helper never prints the key. If the Goodix service runs as SYSTEM, pass
`-Account System`.

A TLS session check and a one-shot activation cycle take a key file or the
community path:

```sh
chmod 600 /path/to/goodix-55b4.psk
sudo ./build/goodix-probe --session-check /path/to/goodix-55b4.psk
./build/goodix-cycle --community 1
```

Do not run write-capable third-party Goodix tools against the device.

## License

This project is licensed under the GNU Lesser General Public License,
version 2.1 or later. See [LICENSE](LICENSE). The attributed public Goodix
configuration is distributed under the MIT license in
[LICENSES/MIT-goodix-fp-dump.txt](LICENSES/MIT-goodix-fp-dump.txt).
