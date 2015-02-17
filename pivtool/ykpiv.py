# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
from ctypes import (Structure, POINTER, c_int, c_ubyte, c_char_p, c_long,
                    c_ulong, c_size_t)
from pivtool.libloader import load_library

_lib = load_library('ykpiv', '0')


def define(name, args, res):
    fn = getattr(_lib, name)
    fn.argtypes = args
    fn.restype = res
    return fn


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
    POINTER(ykpiv_state), POINTER(c_ubyte), c_size_t, c_char_p,
    POINTER(c_size_t), c_ubyte, c_ubyte], ykpiv_rc)
ykpiv_get_version = define('ykpiv_get_version', [POINTER(ykpiv_state), c_char_p,
                                                 c_size_t], ykpiv_rc)
ykpiv_verify = define('ykpiv_verify', [POINTER(ykpiv_state), c_char_p,
                                       POINTER(c_int)], ykpiv_rc)
ykpiv_fetch_object = define('ykpiv_fetch_object', [
    POINTER(ykpiv_state), c_int, POINTER(c_ubyte), POINTER(c_ulong)], ykpiv_rc)
ykpiv_save_object = define('ykpiv_save_object', [
    POINTER(ykpiv_state), c_int, POINTER(c_ubyte), c_size_t], ykpiv_rc)


__all__ = [x for x in globals().keys() if x.lower().startswith('ykpiv')]
