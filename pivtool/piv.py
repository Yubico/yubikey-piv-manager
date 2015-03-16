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
from pivtool import messages as m
from pivtool.utils import der_read, test
from ctypes import (POINTER, byref, create_string_buffer, sizeof, c_ubyte,
                    c_size_t, c_int)

libversion = ykpiv_check_version(None)


class DeviceGoneError(Exception):
    def __init__(self):
        super(DeviceGoneError, self).__init__(m.communication_error)


class PivError(Exception):
    def __init__(self, code):
        message = ykpiv_strerror(code)
        super(PivError, self).__init__(code, message)
        self.code = code
        self.message = message

    def __str__(self):
        return m.ykpiv_error_2 % (self.code, self.message)


def check(rc):
    if rc == YKPIV_PCSC_ERROR:
        raise DeviceGoneError()
    elif rc != YKPIV_OK:
        raise PivError(rc)


KEY_LEN = 24
DEFAULT_KEY = '010203040506070801020304050607080102030405060708'.decode('hex')

CERT_SLOTS = {
    '9a': YKPIV_OBJ_AUTHENTICATION,
    '9c': YKPIV_OBJ_SIGNATURE,
    '9d': YKPIV_OBJ_KEY_MANAGEMENT,
    '9e': YKPIV_OBJ_CARD_AUTH
}

ATTR_NAME = "name"


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

    def _connect(self):
        check(ykpiv_init(byref(self._state), self._verbosity))
        check(ykpiv_connect(self._state, self._reader))

        self._read_version()
        self._read_chuid()
        self._read_cert_index()

    def _read_version(self):
        v = create_string_buffer(10)
        check(ykpiv_get_version(self._state, v, sizeof(v)))
        self._version = v.value

    def _read_chuid(self, first_attempt=True):
        try:
            chuid_data = self.fetch_object(YKPIV_OBJ_CHUID)[29:29+16]
            self._chuid = chuid_data.encode('hex')
        except PivError as e:  # No chuid set?
            if first_attempt:
                self.set_chuid()
                self._read_chuid(False)
            else:
                raise e

    def _read_cert_index(self):
        self._cert_index =  dict([(k, test(self.fetch_object, v,
                                           catches=PivError)) \
                                  for (k, v) in CERT_SLOTS.items()])

    def __del__(self):
        check(ykpiv_done(self._state))

    def _reset(self):
        self.__del__()
        self._connect()
        args = self._cmd._base_args
        if '-P' in args:
            self.verify_pin(args[args.index('-P') + 1])
        if '-k' in args:
            self.authenticate(args[args.index('-k') + 1].decode('hex'))

    @property
    def version(self):
        return self._version

    @property
    def chuid(self):
        return self._chuid

    @property
    def cert_index(self):
        return self._cert_index

    def set_chuid(self):
        try:
            self._cmd.run('-a', 'set-chuid')
        finally:
            self._reset()
        self._read_chuid()

    def authenticate(self, key=None):
        if key is None:
            key = DEFAULT_KEY
        elif len(key) != KEY_LEN:
            raise ValueError('Key must be %d bytes' % KEY_LEN)
        c_key = (c_ubyte * KEY_LEN).from_buffer_copy(key)
        check(ykpiv_authenticate(self._state, c_key))
        self._cmd.set_arg('-k', key.encode('hex'))

    def set_authentication(self, key):
        if len(key) != KEY_LEN:
            raise ValueError('Key must be %d bytes' % KEY_LEN)
        c_key = (c_ubyte * len(key)).from_buffer_copy(key)
        check(ykpiv_set_mgmkey(self._state, c_key))
        self._cmd.set_arg('-k', key.encode('hex'))

    def verify_pin(self, pin):
        if isinstance(pin, unicode):
            pin = pin.encode('utf8')
        buf = create_string_buffer(pin)
        tries = c_int(-1)
        rc = ykpiv_verify(self._state, buf, byref(tries))

        if rc == YKPIV_WRONG_PIN:
            if tries.value > 0:
                raise ValueError(m.wrong_pin_tries_1 % tries.value)
            else:
                raise ValueError(m.pin_blocked)
        check(rc)
        self._cmd.set_arg('-P', pin)

    def set_pin(self, pin):
        if isinstance(pin, unicode):
            pin = pin.encode('utf8')
        if len(pin) > 8:
            raise ValueError(m.pin_too_long)
        try:
            self._cmd.run('-a', 'change-pin', '-N', pin)
            self._cmd.set_arg('-P', pin)
        finally:
            self._reset()

    def set_puk(self, puk, new_puk):
        if isinstance(puk, unicode):
            puk = puk.encode('utf8')
        if isinstance(new_puk, unicode):
            new_puk = new_puk.encode('utf8')
        if len(new_puk) > 8:
            raise ValueError(m.puk_too_long)

        pin = None
        args = self._cmd._base_args
        if '-P' in args:
            pin = args[args.index('-P') + 1]

        try:
            self._cmd.set_arg('-P', puk)
            self._cmd.run('-a', 'change-puk', '-N', new_puk)
        finally:
            self._cmd.set_arg('-P', pin)
            self._reset()

    def fetch_object(self, object_id):
        buf = (c_ubyte * 4096)()
        buf_len = c_size_t(sizeof(buf))

        check(ykpiv_fetch_object(self._state, object_id, buf, buf_len))
        return ''.join(map(chr, buf[:buf_len.value]))

    def save_object(self, object_id, data):
        c_data = (c_ubyte * len(data)).from_buffer_copy(data)
        check(ykpiv_save_object(self._state, object_id, c_data, len(data)))

    def generate(self, slot):
        try:
            return self._cmd.generate(slot)
        finally:
            self._reset()

    def create_csr(self, subject, pubkey_pem, slot):
        try:
            return self._cmd.create_csr(subject, pubkey_pem, slot)
        finally:
            self._reset()

    def import_cert(self, cert_pem, slot, frmt='PEM'):
        try:
            return self._cmd.import_cert(cert_pem, slot, frmt)
        finally:
            self._reset()

    def import_pfx(self, pfx_data, password, slot):
        try:
            return self._cmd.import_pfx(pfx_data, password, slot)
        finally:
            self._reset()

    def read_cert(self, slot):
        try:
            data = self.fetch_object(CERT_SLOTS[slot])
        except PivError:
            return None
        cert, rest = der_read(data, 0x70)
        zipped, rest = der_read(rest, 0x71)
        if zipped != chr(0):
            pass  # TODO: cert is compressed, uncompress.
        return cert

    def delete_cert(self, slot):
        if not self.cert_index.get(slot):
            raise ValueError('No certificate loaded in slot: %s' % slot)

        try:
            return self._cmd.delete_cert(slot)
        finally:
            self._reset()
