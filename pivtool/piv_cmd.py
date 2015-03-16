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


import subprocess


CMD = "yubico-piv-tool"


def check(status, err):
    if status != 0:
        raise ValueError('Error: %s' % err)


class YkPivCmd(object):
    def __init__(self, cmd=CMD, verbosity=0, reader=None, key=None):
        self._base_args = [cmd]
        if verbosity > 0:
            self._base_args.extend(['-v', verbosity])
        if reader:
            self._base_args.extend(['-r', reader])
        if key:
            self._base_args.extend(['-k', key])

    def args(self, *args):
        self._base_args.extend(list(args))

    def set_arg(self, opt, value):
        try:
            index = self._base_args.index(opt)
            if value is None:
                del self._base_args[index]
                del self._base_args[index]
            else:
                self._base_args[index+1] = value
        except ValueError:
            if value is not None:
                self._base_args.extend([opt, value])

    def run(self, *args, **kwargs):
        if subprocess.mswindows:  # Avoid showing console window on Windows
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        else:
            startupinfo = None

        p = subprocess.Popen(self._base_args + list(args),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, startupinfo=startupinfo)
        out, err = p.communicate(**kwargs)
        check(p.returncode, err)

        return out

    def change_pin(self, old_pin, new_pin):
        self.run('-a', 'change-pin', '-P', old_pin, '-N', new_pin)

    def change_puk(self, old_puk, new_puk):
        self.run('-a', 'change-puk', '-P', old_puk, '-N', new_puk)

    def generate(self, slot):
        return self.run('-s', slot, '-a', 'generate')

    def create_csr(self, subject, pem, slot):
        if '-P' not in self._base_args:
            raise ValueError('PIN has not been verified')
        return self.run('-a', 'verify-pin', '-s', slot, '-a',
                        'request-certificate', '-S', subject, input=pem)

    def import_cert(self, pem, slot):
        if '-k' not in self._base_args:
            raise ValueError('Management key has not been provided')
        return self.run('-s', slot, '-a', 'import-certificate', input=pem)

    def import_pfx(self, pfx_data, password, slot):
        if '-k' not in self._base_args:
            raise ValueError('Management key has not been provided')
        return self.run('-s', slot, '-K', 'PKCS12', '-p', password,
                        '-a', 'import-key', '-a', 'import-certificate',
                        input=pfx_data*2)

    def delete_cert(self, slot):
        if '-k' not in self._base_args:
            raise ValueError('Management key has not been provided')
        return self.run('-s', slot, '-a', 'delete-certificate')
