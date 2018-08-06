SET "PATH=%PATH%;C:\Program Files (x86)\Common Files\Microsoft\Visual C++ for Python\9.0\WinSDK\Bin"
SET "PATH=%PATH%;C:\Program Files (x86)\NSIS"
SET "PATH=%PATH%;C:\Python27\Lib\site-packages\PySide-1.2.4-py2.7-win-amd64.egg\PySide"
SET "PIVTOOL_VERSION=1.4.4"

REM Download yubico-piv-tool DLLs
REM powershell -Command "(New-Object Net.WebClient).DownloadFile('https://developers.yubico.com/yubico-piv-tool/Releases/yubico-piv-tool-%PIVTOOL_VERSION%-win32.zip', 'yubico-piv-tool-%PIVTOOL_VERSION%-win32.zip')"
REM 7z e "-olib yubico-piv-tool-%PIVTOOL_VERSION%-win32.zip" bin/

python setup.py qt_resources
python setup.py executable
