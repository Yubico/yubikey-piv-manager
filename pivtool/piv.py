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

from pivtool.ykpiv import *
from ctypes import (POINTER, byref, create_string_buffer, sizeof, c_ubyte,
                    c_size_t, c_int)


def check(rc):
    if rc != YKPIV_OK:
        raise ValueError('Error: %s' % ykpiv_strerror(rc))


KEY_LEN = 24
DEFAULT_KEY = '010203040506070801020304050607080102030405060708'


class YkPiv(object):
    def __init__(self, verbosity=0, reader=chr(0)):
        self._state = POINTER(ykpiv_state)()
        check(ykpiv_init(byref(self._state), verbosity))
        check(ykpiv_connect(self._state, reader))

        v = create_string_buffer(10)
        check(ykpiv_get_version(self._state, v, sizeof(v)))
        self._version = v.value

    def __del__(self):
        check(ykpiv_done(self._state))

    @property
    def version(self):
        return self._version

    def authenticate(self, hex_key=DEFAULT_KEY):
        key = (c_ubyte * KEY_LEN)()
        key_len = c_size_t(sizeof(key))
        check(ykpiv_hex_decode(hex_key, len(hex_key), key, byref(key_len)))
        check(ykpiv_authenticate(self._state, key))

    def verify_pin(self, pin):
        if len(pin) > 8:
            raise ValueError('PIN must be no more than 8 digits long.')
        pin = create_string_buffer(pin)
        tries = c_int(-1)
        rc = ykpiv_verify(self._state, pin, byref(tries))

        if rc == YKPIV_WRONG_PIN:
            if tries._type_value > 0:
                raise ValueError('PIN verification failed. %d tries remaining' %
                                 tries.value)
            else:
                raise ValueError('PIN blocked.')
        check(rc)

    def fetch_object(self, object_id):
        buf = (c_ubyte * 1024)()
        buf_len = c_size_t(sizeof(buf))

        check(ykpiv_fetch_object(self._state, object_id, buf, buf_len))
        return buf[:buf_len.value]
