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

from ctypes import (Structure, POINTER, c_int, c_ubyte, c_char_p, c_long,
                    c_ulong, c_size_t, byref, sizeof)
from pivman.yubicommon.ctypes import CLibrary
from pivman.yubicommon.compat import int2byte


ykpiv_state = type('ykpiv_state', (Structure,), {})
ykpiv_rc = c_int


class YKPIV(object):
    OK = 0
    MEMORY_ERROR = -1
    PCSC_ERROR = -2
    SIZE_ERROR = -3
    APPLET_ERROR = -4
    AUTHENTICATION_ERROR = -5
    RANDOMNESS_ERROR = -6
    GENERIC_ERROR = -7
    KEY_ERROR = -8
    PARSE_ERROR = -9
    WRONG_PIN = -10
    INVALID_OBJECT = -11
    ALGORITHM_ERROR = -12
    PIN_LOCKED = -13

    class OBJ(object):
        CAPABILITY = 0x5fc107
        CHUID = 0x5fc102
        AUTHENTICATION = 0x5fc105  # cert for 9a key
        FINGERPRINTS = 0x5fc103
        SECURITY = 0x5fc106
        FACIAL = 0x5fc108
        PRINTED = 0x5fc109
        SIGNATURE = 0x5fc10a  # cert for 9c key
        KEY_MANAGEMENT = 0x5fc10b  # cert for 9d key
        CARD_AUTH = 0x5fc101  # cert for 9e key
        DISCOVERY = 0x7e
        KEY_HISTORY = 0x5fc10c
        IRIS = 0x5fc121

    class ALGO(object):
        TDEA = 0x03
        RSA1024 = 0x06
        RSA2048 = 0x07
        ECCP256 = 0x11
        ECCP384 = 0x14

    class PINPOLICY(object):
        DEFAULT = 0x00
        NEVER = 0x01
        ONCE = 0x02
        ALWAYS = 0x03

    class TOUCHPOLICY(object):
        DEFAULT = 0x00
        NEVER = 0x01
        ALWAYS = 0x02
        CACHED = 0x03


class LibYkPiv(CLibrary):
    ykpiv_strerror = [ykpiv_rc], c_char_p
    ykpiv_strerror_name = [ykpiv_rc], c_char_p

    ykpiv_init = [POINTER(POINTER(ykpiv_state)), c_int], ykpiv_rc
    ykpiv_done = [POINTER(ykpiv_state)], ykpiv_rc

    ykpiv_connect = [POINTER(ykpiv_state), c_char_p], ykpiv_rc
    ykpiv_disconnect = [POINTER(ykpiv_state)], ykpiv_rc
    ykpiv_transfer_data = [POINTER(ykpiv_state), POINTER(c_ubyte),
                           POINTER(c_ubyte), c_long, POINTER(c_ubyte),
                           POINTER(c_ulong), POINTER(c_int)], ykpiv_rc
    ykpiv_authenticate = [POINTER(ykpiv_state), POINTER(c_ubyte)], ykpiv_rc
    ykpiv_set_mgmkey = [POINTER(ykpiv_state), POINTER(c_ubyte)], ykpiv_rc
    ykpiv_change_pin = [POINTER(ykpiv_state), c_char_p, c_size_t, c_char_p,
                        c_size_t, POINTER(c_int)], ykpiv_rc
    ykpiv_change_puk = [POINTER(ykpiv_state), c_char_p, c_size_t, c_char_p,
                        c_size_t, POINTER(c_int)], ykpiv_rc
    ykpiv_unblock_pin = [POINTER(ykpiv_state), c_char_p, c_size_t, c_char_p,
                         c_size_t, POINTER(c_int)], ykpiv_rc
    ykpiv_hex_decode = [c_char_p, c_size_t, POINTER(c_ubyte), POINTER(c_size_t)
                        ], ykpiv_rc
    ykpiv_sign_data = [POINTER(ykpiv_state), POINTER(c_ubyte), c_size_t,
                       POINTER(c_ubyte), POINTER(c_size_t), c_ubyte, c_ubyte
                       ], ykpiv_rc
    ykpiv_get_version = [POINTER(ykpiv_state), c_char_p, c_size_t], ykpiv_rc
    ykpiv_verify = [POINTER(ykpiv_state), c_char_p, POINTER(c_int)], ykpiv_rc
    ykpiv_fetch_object = [POINTER(ykpiv_state), c_int, POINTER(c_ubyte),
                          POINTER(c_ulong)], ykpiv_rc
    ykpiv_save_object = [POINTER(ykpiv_state), c_int, POINTER(c_ubyte),
                         c_size_t], ykpiv_rc

    ykpiv_check_version = [c_char_p], c_char_p

    def reset(self, state):
        data = (c_ubyte * 4).from_buffer_copy(b'\0\xfb\0\0')
        buf = (c_ubyte * 256)()
        buf_len = c_size_t(sizeof(buf))
        sw = c_int(-1)
        self.ykpiv_transfer_data(state, data, None, 0, buf, byref(buf_len),
                                 byref(sw))
        if sw.value == 0x9000:
            return YKPIV.OK
        return sw.value

    def generate_key(self, state, slot, algorithm, pin_policy, touch_policy):
        templ = (c_ubyte * 4).from_buffer_copy(b'\0\x47\0' + int2byte(slot))
        in_data = (c_ubyte * 11).from_buffer_copy(
            b'\xac\x09\x80\x01' + int2byte(algorithm) +
            b'\xaa\x01' + int2byte(pin_policy) +
            b'\xab\x01' + int2byte(touch_policy)
        )
        sw = c_int(0)
        buf = (c_ubyte * 1024)()
        buf_len = c_size_t(sizeof(buf))
        self.ykpiv_transfer_data(state, templ, in_data, len(in_data),
                                 buf, byref(buf_len), byref(sw))
        if sw.value == 0x9000:
            return YKPIV.OK, b''.join(map(int2byte, buf[:buf_len.value]))
        return sw.value, b''


ykpiv = LibYkPiv('ykpiv', '1')
