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

from pivtool.libykpiv import *
from pivtool.piv_cmd import YkPivCmd
from pivtool.storage import settings
from ctypes import (POINTER, byref, create_string_buffer, sizeof, c_ubyte,
                    c_size_t, c_int)
import time


def check(rc):
    if rc != YKPIV_OK:
        raise ValueError('Error %d: %s' % (rc, ykpiv_strerror(rc)))


KEY_LEN = 24
DEFAULT_KEY = '010203040506070801020304050607080102030405060708'

ATTR_NAME = "name"
ATTR_PIN_CHANGED = "pinChanged"


def rename_group(old_name, new_name):
    data = {}
    try:
        settings.beginGroup(old_name)
        for key in settings.allKeys():
            data[key] = settings.value(key)
    finally:
        settings.endGroup()
    settings.remove(old_name)

    try:
        settings.beginGroup(new_name)
        for key in data:
            settings.setValue(key, data[key])
    finally:
        settings.endGroup()


class YkPiv(object):
    def __init__(self, verbosity=0, reader=None):
        self._cmd = YkPivCmd(verbosity=verbosity, reader=reader)

        self._state = POINTER(ykpiv_state)()
        if reader is None:
            reader = chr(0)

        self._chuid = None
        self._verbosity = verbosity
        self._reader = reader

        self._connect()

    def get(self, key, default=None):
        return settings.value('%s/%s' % (self.chuid, key), default)

    def __setitem__(self, key, value):
        settings.setValue('%s/%s' % (self.chuid, key), value)

    def __delitem__(self, key):
        settings.remove('%s/%s' % (self.chuid, key))

    def __getitem__(self, key):
        return self.get(key)

    def __nonzero__(self):
        return True

    def __len__(self):
        try:
            settings.beginGroup('%s' % self.chuid)
            return len(settings.childKeys())
        finally:
            settings.endGroup()

    def _connect(self):
        check(ykpiv_init(byref(self._state), self._verbosity))
        check(ykpiv_connect(self._state, self._reader))

        self._read_version()
        self._read_chuid()

    def _read_version(self):
        v = create_string_buffer(10)
        check(ykpiv_get_version(self._state, v, sizeof(v)))
        self._version = v.value

    def _read_chuid(self, first_attempt=True):
        try:
            chuid_data = self.fetch_object(YKPIV_OBJ_CHUID)[29:29+16]
            self._chuid = ''.join(map(chr, chuid_data)).encode('hex')
        except ValueError as e:  # No chuid set?
            if first_attempt:
                self.set_chuid()
                self._read_chuid(False)
            else:
                raise e

    def __del__(self):
        check(ykpiv_done(self._state))

    def _reset(self):
        self.__del__()
        self._connect()

    @property
    def name(self):
        return self.get(ATTR_NAME, 'YubiKey NEO')

    @name.setter
    def name(self, new_name):
        self[ATTR_NAME] = new_name

    @property
    def version(self):
        return self._version

    @property
    def chuid(self):
        return self._chuid

    def set_chuid(self):
        old_chuid = self._chuid
        self._cmd.run('-a', 'set-chuid')
        self._reset()
        self._read_chuid()
        rename_group(old_chuid, self.chuid)

    def authenticate(self, hex_key=DEFAULT_KEY):
        key = (c_ubyte * KEY_LEN)()
        key_len = c_size_t(sizeof(key))
        check(ykpiv_hex_decode(hex_key, len(hex_key), key, byref(key_len)))
        check(ykpiv_authenticate(self._state, key))
        self._cmd.set_arg('-k', hex_key)

    def verify_pin(self, pin):
        if len(pin) > 8:
            raise ValueError('PIN must be no more than 8 digits long.')
        buf = create_string_buffer(pin)
        tries = c_int(-1)
        rc = ykpiv_verify(self._state, buf, byref(tries))

        if rc == YKPIV_WRONG_PIN:
            if tries._type_value > 0:
                raise ValueError('PIN verification failed. %d tries remaining' %
                                 tries.value)
            else:
                raise ValueError('PIN blocked.')
        check(rc)
        self._cmd.set_arg('-P', pin)

    def set_pin(self, pin):
        self._cmd.run('-a', 'change-pin', '-N', pin)
        self._reset()
        self.verify_pin(pin)
        self[ATTR_PIN_CHANGED] = int(time.time())

    @property
    def pin_last_changed(self):
        last_changed = self[ATTR_PIN_CHANGED]
        if last_changed is None:
            return None
        return int(last_changed)

    def fetch_object(self, object_id):
        buf = (c_ubyte * 1024)()
        buf_len = c_size_t(sizeof(buf))

        check(ykpiv_fetch_object(self._state, object_id, buf, buf_len))
        return buf[:buf_len.value]

    def save_object(self, object_id, data):
        check(ykpiv_save_object(self._state, object_id, data, sizeof(data)))
