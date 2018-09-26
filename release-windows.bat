SET VERSION="%1"

ECHO "Building release of version: %VERSION%"

SET RELEASE_DIR=".\dist"

SET "PATH=%PATH%;C:\Program Files (x86)\NSIS"
SET "PATH=%PATH%;C:\Program Files (x86)\Common Files\Microsoft\Visual C++ for Python\9.0\WinSDK\Bin"

signtool sign /fd SHA256 /t http://timestamp.verisign.com/scripts/timstamp.dll "%RELEASE_DIR%\YubiKey PIV Manager"\pivman.exe
makensis -D"VERSION=%VERSION%" resources\win-installer.nsi
signtool sign /fd SHA256 /t http://timestamp.verisign.com/scripts/timstamp.dll "%RELEASE_DIR%\yubikey-piv-manager-%VERSION%-win.exe"
gpg --detach-sign "yubikey-piv-manager-%VERSION%-win.exe"
