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
                    c_ulong, c_size_t)
from pivtool.libloader import load_library

_lib = load_library('ykpiv', '1')


def define(name, args, res):
    fn = getattr(_lib, name)
    fn.argtypes = args
    fn.restype = res
    return fn


YKPIV_OK = 0
YKPIV_MEMORY_ERROR = -1
YKPIV_PCSC_ERROR = -2
YKPIV_SIZE_ERROR = -3
YKPIV_APPLET_ERROR = -4
YKPIV_AUTHENTICATION_ERROR = -5
YKPIV_RANDOMNESS_ERROR = -6
YKPIV_GENERIC_ERROR = -7
YKPIV_KEY_ERROR = -8
YKPIV_PARSE_ERROR = -9
YKPIV_WRONG_PIN = -10
YKPIV_INVALID_OBJECT = -11
YKPIV_ALGORITHM_ERROR = -12

YKPIV_OBJ_CAPABILITY = 0x5fc107
YKPIV_OBJ_CHUID = 0x5fc102
YKPIV_OBJ_AUTHENTICATION = 0x5fc105  # cert for 9a key
YKPIV_OBJ_FINGERPRINTS = 0x5fc103
YKPIV_OBJ_SECURITY = 0x5fc106
YKPIV_OBJ_FACIAL = 0x5fc108
YKPIV_OBJ_PRINTED = 0x5fc109
YKPIV_OBJ_SIGNATURE = 0x5fc10a  # cert for 9c key
YKPIV_OBJ_KEY_MANAGEMENT = 0x5fc10b  # cert for 9d key
YKPIV_OBJ_CARD_AUTH = 0x5fc101  # cert for 9e key
YKPIV_OBJ_DISCOVERY = 0x7e
YKPIV_OBJ_KEY_HISTORY = 0x5fc10c
YKPIV_OBJ_IRIS = 0x5fc121

YKPIV_ALGO_3DES = 0x03
YKPIV_ALGO_RSA1024 = 0x06
YKPIV_ALGO_RSA2048 = 0x07
YKPIV_ALGO_ECCP256 = 0x11

ykpiv_state = type('ykpiv_state', (Structure,), {})
ykpiv_rc = c_int

ykpiv_strerror = define('ykpiv_strerror', [ykpiv_rc], c_char_p)
ykpiv_strerror_name = define('ykpiv_strerror_name', [ykpiv_rc], c_char_p)


ykpiv_init = define('ykpiv_init', [POINTER(POINTER(ykpiv_state)), c_int],
                    ykpiv_rc)
ykpiv_done = define('ykpiv_done', [POINTER(ykpiv_state)], ykpiv_rc)

ykpiv_connect = define('ykpiv_connect', [POINTER(ykpiv_state), c_char_p],
                       ykpiv_rc)
ykpiv_disconnect = define('ykpiv_disconnect', [POINTER(ykpiv_state)], ykpiv_rc)
ykpiv_transfer_data = define('ykpiv_transfer_data', [
    POINTER(ykpiv_state), POINTER(c_ubyte), POINTER(c_ubyte), c_long,
    POINTER(c_ubyte), POINTER(c_ulong), POINTER(c_int)], ykpiv_rc)
ykpiv_authenticate = define('ykpiv_authenticate', [POINTER(ykpiv_state),
                                                   POINTER(c_ubyte)], ykpiv_rc)
ykpiv_set_mgmkey = define('ykpiv_set_mgmkey', [POINTER(ykpiv_state),
                                               POINTER(c_ubyte)], ykpiv_rc)
ykpiv_hex_decode = define('ykpiv_hex_decode', [
    c_char_p, c_size_t, POINTER(c_ubyte), POINTER(c_size_t)], ykpiv_rc)
ykpiv_sign_data = define('ykpiv_sign_data', [
    POINTER(ykpiv_state), POINTER(c_ubyte), c_size_t, POINTER(c_ubyte),
    POINTER(c_size_t), c_ubyte, c_ubyte], ykpiv_rc)
ykpiv_get_version = define('ykpiv_get_version', [POINTER(ykpiv_state), c_char_p,
                                                 c_size_t], ykpiv_rc)
ykpiv_verify = define('ykpiv_verify', [POINTER(ykpiv_state), c_char_p,
                                       POINTER(c_int)], ykpiv_rc)
ykpiv_fetch_object = define('ykpiv_fetch_object', [
    POINTER(ykpiv_state), c_int, POINTER(c_ubyte), POINTER(c_ulong)], ykpiv_rc)
ykpiv_save_object = define('ykpiv_save_object', [
    POINTER(ykpiv_state), c_int, POINTER(c_ubyte), c_size_t], ykpiv_rc)

ykpiv_check_version = define('ykpiv_check_version', [c_char_p], c_char_p)


__all__ = [x for x in globals().keys() if x.lower().startswith('ykpiv')]
