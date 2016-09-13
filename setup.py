# Copyright (c) 2014 Yubico AB
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Additional permission under GNU GPL version 3 section 7
#
# If you modify this program, or any covered work, by linking or
# combining it with the OpenSSL project's OpenSSL library (or a
# modified version of that library), containing parts covered by the
# terms of the OpenSSL or SSLeay licenses, We grant you additional
# permission to convey the resulting work. Corresponding Source for a
# non-source form of such a combination shall include the source code
# for the parts of OpenSSL used as well as that of the covered work.

from pivman.yubicommon.setup.exe import executable
from pivman.yubicommon.setup.qt import qt_resources
from pivman.yubicommon.setup import setup


setup(
    name='yubikey-piv-manager',
    long_name='YubiKey PIV Manager',
    author='Dain Nilsson',
    author_email='dain@yubico.com',
    maintainer='Yubico Open Source Maintainers',
    maintainer_email='ossmaint@yubico.com',
    url='https://github.com/Yubico/yubikey-piv-manager',
    description='Tool for configuring your PIV-enabled YubiKey.',
    license='GPLv3+',
    entry_points={
        'gui_scripts': ['pivman=pivman.__main__:main']
    },
    install_requires=['cryptography', 'PySide'],
    yc_requires=['ctypes', 'qt'],
    test_suite='test',
    tests_require=[''],
    cmdclass={'executable': executable, 'qt_resources': qt_resources('pivman')},
    classifiers=[
        'License :: OSI Approved :: ' +
        'GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Development Status :: 5 - Production/Stable',
        'Environment :: X11 Applications :: Qt',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities'
    ]
)
