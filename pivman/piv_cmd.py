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
import re


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

    def __init__(self, cmd=find_cmd(), verbosity=0, reader=None, key=None):
        self._base_args = [cmd]
        if verbosity > 0:
            self._base_args.extend(['-v', str(verbosity)])
        if reader:
            self._base_args.extend(['-r', reader])
        if key:
            self._base_args.extend(['-k', key])

    def set_arg(self, opt, value):
        if isinstance(value, bytes):
            value = value.decode('utf8')
        self._base_args = set_arg(self._base_args, opt, value)

    def run(self, *args, **kwargs):
        if sys.platform == 'win32':  # Avoid showing console window on Windows
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        else:
            startupinfo = None

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
                             startupinfo=startupinfo)
        out, err = p.communicate(**kwargs)
        check(p.returncode, err)

        return out

    def tool_version(self):
        v_bytes = self.run('-V', '-')
        return re.search(rb'\d+.\d+.\d+', v_bytes).group()

    def status(self):
        return self.run('-a', 'status')

    def version(self):
        v_bytes = self.run('-a', 'version')
        return re.search(rb'\d+.\d+.\d+', v_bytes).group()

    def set_mgm_key(self, new_key):
        self.run('-a', 'set-mgm-key', '-n', new_key)
        self.set_arg('-k', new_key)

    def change_pin(self, new_pin):
        if '-P' not in self._base_args:
            raise ValueError('PIN has not been verified')
        self.run('-a', 'change-pin', '-N', new_pin)
        self.set_arg('-P', new_pin)

    def change_puk(self, old_puk, new_puk):
        self.run('-a', 'change-puk', '-P', old_puk, '-N', new_puk)

    def reset_pin(self, puk, new_pin):
        self.run('-a', 'unblock-pin', '-P', puk, '-N', new_pin)
        self.set_arg('-P', new_pin)

    def generate(self, slot, algorithm, pin_policy, touch_policy):
        return self.run('-s', slot, '-a', 'generate', '-A', algorithm,
                        '--pin-policy', pin_policy, '--touch-policy',
                        'always' if touch_policy else 'never')

    def create_csr(self, subject, pem, slot):
        if '-P' not in self._base_args:
            raise ValueError('PIN has not been verified')
        return self.run('-a', 'verify-pin', '-s', slot, '-a',
                        'request-certificate', '-S', subject, input=pem)

    def create_ssc(self, subject, pem, slot, valid_days=365):
        if '-P' not in self._base_args:
            raise ValueError('PIN has not been verified')
        return self.run('-a', 'verify-pin', '-s', slot, '-a',
                        'selfsign-certificate', '-S', subject,
                        '--valid-days', str(valid_days), input=pem)

    def import_cert(self, data, slot, frmt='PEM', password=None):
        return self._do_import('import-cert', data, slot, frmt, password)

    def import_key(self, data, slot, frmt, password, pin_policy, touch_policy):
        return self._do_import('import-key', data, slot, frmt, password,
                               '--pin-policy', pin_policy, '--touch-policy',
                               'always' if touch_policy else 'never')

    def _do_import(self, action, data, slot, frmt, password, *args):
        if '-k' not in self._base_args:
            raise ValueError('Management key has not been provided')
        args = ['-s', slot, '-K', frmt, '-a', action] + list(args)
        if password is not None:
            args.extend(['-p', password])
        return self.run(*args, input=data)

    def delete_cert(self, slot):
        if '-k' not in self._base_args:
            raise ValueError('Management key has not been provided')
        return self.run('-s', slot, '-a', 'delete-certificate')

    def read_object(self, object_id):
        return self.run('-a', 'read-object', '-f', 'binary', '--id',
                        hex(object_id))

    def write_object(self, object_id, data):
        self.run('-a', 'write-object', '-f', 'binary', '--id', hex(object_id),
                 input=data)
