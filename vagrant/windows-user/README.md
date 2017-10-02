Windows VM for testing releases
===

This is a blank Windows 10 VM with Edge installed.


Usage
---

Go to https://github.com/Yubico/yubikey-piv-manager/releases , download and
install a Windows release, run
`C:\Program Files (x86)\Yubico\YubiKey PIV Manager\pivman.exe` and connect a
YubiKey.

This `Vagrantfile` sets up USB forwarding in VirtualBox of YubiKey 4s with _all_
of the OTP+U2F+CCID transports enabled (device ID `1050:0407`). If you use a
different VM engine or YubiKey, adjust these settings as necessary.
