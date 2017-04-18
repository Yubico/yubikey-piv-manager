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
import sys
import os


CMD = 'yubico-piv-tool'

if getattr(sys, 'frozen', False):
    # we are running in a PyInstaller bundle
    basedir = sys._MEIPASS
else:
    # we are running in a normal Python environment
    basedir = os.path.dirname(__file__)


def find_cmd():
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    cmd = CMD + '.exe' if sys.platform == 'win32' else CMD
    paths = [basedir] + os.environ.get('PATH', '').split(os.pathsep)
    for path in paths:
        path = path.strip('"')
        fpath = os.path.join(path, cmd)
        if is_exe(fpath):
            return fpath
    return None


def check(status, err):
    if status != 0:
        raise ValueError('Error: %s' % err)


def set_arg(args, opt, value):
    args = list(args)
    if opt != '-a' and opt in args:
        index = args.index(opt)
        if value is None:
            del args[index]
            del args[index]
        else:
            args[index + 1] = value
    elif value is not None:
        args.extend([opt, value])
    return args


class YkPivCmd(object):

    _pin = None
    _key = None

    def __init__(self, cmd=find_cmd(), verbosity=0, reader=None, key=None):
        self._base_args = [cmd]
        if verbosity > 0:
            self._base_args.extend(['-v', str(verbosity)])
        if reader:
            self._base_args.extend(['-r', reader])
        if key:
            self._key = key

    def set_arg(self, opt, value):
        if isinstance(value, bytes):
            value = value.decode('utf8')
        self._base_args = set_arg(self._base_args, opt, value)

    def run(self, *args, **kwargs):
        full_args = list(self._base_args)
        new_args = list(args)
        while new_args:
            full_args = set_arg(full_args, new_args.pop(0), new_args.pop(0))

        if '-k' in full_args:  # Workaround for passing key in 1.1.0
            i = full_args.index('-k')
            full_args = full_args[:i] + ['-k' + full_args[i+1]] \
                + full_args[i+2:]
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        out, err = p.communicate(**kwargs)
        check(p.returncode, err)

        return out

    def get_startup_info(self):
        if sys.platform == 'win32':  # Avoid showing console window on Windows
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        else:
            startupinfo = None
        return startupinfo

    def status(self):
        return self.run('-a', 'status')

    def change_pin(self, new_pin):
        if self._pin is None:
            raise ValueError('PIN has not been verified')
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-a', 'change-pin')
        full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        p.stdin.write(self._pin + '\n')
        p.stdin.write(new_pin + '\n')
        p.stdin.flush()
        out, err = p.communicate()
        check(p.returncode, err)
        self._pin = new_pin

    def change_puk(self, old_puk, new_puk):
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-a', 'change-puk')
        full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        p.stdin.write(old_puk + '\n')
        p.stdin.write(new_puk + '\n')
        p.stdin.flush()
        out, err = p.communicate()
        check(p.returncode, err)

    def reset_pin(self, puk, new_pin):
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-a', 'unblock-pin')
        full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        p.stdin.write(puk + '\n')
        p.stdin.write(new_pin + '\n')
        p.stdin.flush()
        out, err = p.communicate()
        check(p.returncode, err)

    def set_chuid(self):
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-a', 'set-chuid')
        if self._key is not None:
            full_args.append('-k')
            full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        if self._key is not None:
            p.stdin.write(self._key + '\n')
            p.stdin.flush()
        out, err = p.communicate()
        check(p.returncode, err)

    def generate(self, slot, algorithm, pin_policy, touch_policy):
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-s', slot)
        full_args = set_arg(full_args, '-a', 'generate')
        full_args = set_arg(full_args, '-A', algorithm)
        full_args = set_arg(full_args, '--pin-policy', pin_policy)
        full_args = set_arg(
            full_args, '--touch-policy', 'always' if touch_policy else 'never')
        full_args.append('-k')
        full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        p.stdin.write(self._key + '\n')
        p.stdin.flush()
        out, err = p.communicate()
        check(p.returncode, err)
        return out

    def create_csr(self, subject, pem, slot):
        if self._pin is None:
            raise ValueError('PIN has not been verified')
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-a', 'verify-pin')
        full_args = set_arg(full_args, '-s', slot)
        full_args = set_arg(full_args, '-a', 'request-certificate')
        full_args = set_arg(full_args, '-S', subject)
        full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        p.stdin.write(self._pin + '\n')
        p.stdin.flush()
        out, err = p.communicate(input=pem)
        check(p.returncode, err)
        return out

    def create_ssc(self, subject, pem, slot, valid_days=365):
        if self._pin is None:
            raise ValueError('PIN has not been verified')
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-a', 'verify-pin')
        full_args = set_arg(full_args, '-s', slot)
        full_args = set_arg(full_args, '-a', 'selfsign-certificate')
        full_args = set_arg(full_args, '-S', subject)
        full_args = set_arg(full_args, '--valid-days', str(valid_days))
        full_args.append('-k')
        full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        p.stdin.write(self._pin + '\n')
        p.stdin.write(self._key + '\n')
        p.stdin.flush()
        out, err = p.communicate(input=pem)
        check(p.returncode, err)
        return out

    def import_cert(self, data, slot, frmt='PEM', password=None):
        return self._do_import('import-cert', data, slot, frmt, password)

    def import_key(self, data, slot, frmt, password, pin_policy, touch_policy):
        return self._do_import('import-key', data, slot, frmt, password,
                               '--pin-policy', pin_policy, '--touch-policy',
                               'always' if touch_policy else 'never')

    def _do_import(self, action, data, slot, frmt, password, *args):
        if self._key is None:
            raise ValueError('Management key has not been provided')
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-s', slot)
        full_args = set_arg(full_args, '-K', frmt)
        full_args = set_arg(full_args, '-a', action)
        new_args = list(args)
        while new_args:
            full_args = set_arg(full_args, new_args.pop(0), new_args.pop(0))
        full_args.append('-k')
        full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        if password is not None:
            p.stdin.write(password + '\n')
        p.stdin.write(self._key + '\n')
        p.stdin.flush()
        # A small sleep is needed to get yubico-piv-tool
        # to read properly in all cases.
        import time
        time.sleep(0.1)
        out, err = p.communicate(input=data)
        check(p.returncode, err)
        return out

    def delete_cert(self, slot):
        if self._key is None:
            raise ValueError('Management key has not been provided')
        full_args = list(self._base_args)
        full_args = set_arg(full_args, '-a', 'delete-certificate')
        full_args = set_arg(full_args, '-s', slot)
        full_args.append('-k')
        full_args.append('--stdin-input')
        p = subprocess.Popen(full_args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             startupinfo=self.get_startup_info())
        p.stdin.write(self._key + '\n')
        p.stdin.flush()
        out, err = p.communicate()
        check(p.returncode, err)
        return out
