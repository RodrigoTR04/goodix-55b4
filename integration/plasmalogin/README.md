# Plasma Login Manager fingerprint integration

This integration adds an explicit Fingerprint action to Plasma Login Manager
without placing `pam_fprintd` in the password PAM stack. That keeps cold-boot
password login immediate: Linux-PAM can only run one conversation at a time, so
a fingerprint rule in `plasmalogin` or `system-auth` would wait for a reader
timeout before accepting a password.

It targets source commit `f1688d734227510068a4eab54e67b9528b5444d5` (Plasma
Login Manager 6.7.3).

`fingerprint-login.patch` adds a Fingerprint button and a distinct greeter
message. The daemon starts its existing authentication/session helper with the
`plasmalogin-fingerprint` PAM service only for that action. Ordinary login
continues through the unchanged `plasmalogin` service.

The fingerprint action starts only after the user is selected and the button is
pressed. The PAM prompt therefore appears before the user touches the reader,
which this image sensor needs so a resting finger is not mixed into the
absent-finger background. A failed or timed-out attempt returns the existing
login-failed message and does not alter the password stack.

The PAM service is the same shape as KDE’s lock-screen `kde-fingerprint`
service: fingerprint authentication, then the usual account and session
policy, with password explicitly denied. Screen unlock stays on
`kde-fingerprint`. Global `system-auth`, SDDM, sudo, Polkit, and KDE Wallet
are not modified.

Build a matching stage from a root-owned checkout of this repository and a
Plasma Login Manager tree at the pin above, then install the three staged
executables together with the PAM service:

```
sudo /root/goodix-55b4/tools/build-plasmalogin-fingerprint.sh \
    /root/plasma-login-manager /root/plasmalogin-fingerprint-stage
sudo /root/goodix-55b4/tools/install-plasmalogin-fingerprint.sh \
    install /root/plasmalogin-fingerprint-stage
```

The installer backs up the package-owned binaries and prints the exact rollback
command. It does not restart the active display manager; reboot after install
so a cold greeter loads the matching daemon, helper, and greeter.

Do not install Plasma Login Manager’s own PAM files from that build
(`INSTALL_PAM_CONFIGURATION` stays off). Only `plasmalogin-fingerprint` is
added under `/etc/pam.d`, and only when `pam_fprintd.so` is present.
