net use Z: \\VBOXSVR\vagrant

REM Install Chocolatey
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

choco install python2 -y
choco install vcpython27 -y
choco install nsis -y
choco install 7zip -y

pip install --only-binary pyside pyside pycrypto pyinstaller
