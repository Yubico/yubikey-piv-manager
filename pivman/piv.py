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

from pivman.libykpiv import YKPIV, ykpiv, ykpiv_state
from pivman import messages as m
from pivman.utils import der_read, tlv
from pivman.yubicommon.compat import text_type, int2byte
from ctypes import (POINTER, byref, create_string_buffer, sizeof, c_ubyte,
                    c_size_t, c_int)
from binascii import a2b_hex, b2a_hex
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from hashlib import sha256
import re
import os
import struct
import datetime


_YKPIV_MIN_VERSION = b'1.2.0'

libversion = ykpiv.ykpiv_check_version(_YKPIV_MIN_VERSION)
if not libversion:
    raise Exception('libykpiv >= %s required' % _YKPIV_MIN_VERSION)


class DeviceGoneError(Exception):

    def __init__(self):
        super(DeviceGoneError, self).__init__(m.communication_error)


class PivError(Exception):

    def __init__(self, code):
        message = ykpiv.ykpiv_strerror(code).decode('utf8')
        super(PivError, self).__init__(code, message)
        self.code = code
        self.message = message

    def __str__(self):
        return m.ykpiv_error_2 % (self.code, self.message)


class WrongPinError(ValueError):
    m_tries_1 = m.wrong_pin_tries_1
    m_blocked = m.pin_blocked

    def __init__(self, tries):
        super(WrongPinError, self).__init__(self.m_tries_1 % tries
                                            if tries > 0 else self.m_blocked)
        self.tries = tries

    @property
    def blocked(self):
        return self.tries < 1


class WrongPukError(WrongPinError):
    m_tries_1 = m.wrong_puk_tries_1
    m_blocked = m.puk_blocked


def check(rc):
    if rc == YKPIV.PCSC_ERROR:
        raise DeviceGoneError()
    elif rc != YKPIV.OK:
        raise PivError(rc)


def wrap_puk_error(error):
    match = TRIES_PATTERN.search(str(error))
    if match:
        raise WrongPukError(int(match.group(1)))
    raise WrongPukError(0)


KEY_LEN = 24
DEFAULT_KEY = a2b_hex(b'010203040506070801020304050607080102030405060708')

KEY_SLOTS = {
    '9a': 0x9a,
    '9c': 0x9c,
    '9d': 0x9d,
    '9e': 0x9e
}

CERT_SLOTS = {
    '9a': YKPIV.OBJ.AUTHENTICATION,
    '9c': YKPIV.OBJ.SIGNATURE,
    '9d': YKPIV.OBJ.KEY_MANAGEMENT,
    '9e': YKPIV.OBJ.CARD_AUTH
}

ATTR_NAME = 'name'

TRIES_PATTERN = re.compile(r'now (\d+) tries')


def _generate_chuid():
    val = a2b_hex(b'3019d4e739da739ced39ce739d836858210842108421384210c3f53410')
    val += os.urandom(16)
    val += a2b_hex(b'350832303330303130313e00fe00')
    return val


def _generate_ccc():
    val = a2b_hex(b'f015a000000116ff02')
    val += os.urandom(14)
    val += a2b_hex(b'f10121f20121f300f40100f50110f600f700fa00fb00fc00fd00fe00')
    return val


def _pubkey_to_pem(algo, data):
    # TODO: Handle the rest...
    if algo == YKPIV.ALGO.ECCP256:
        curve = ec.SECP256R1()
        numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(curve,
                                                                   data[-65:])
        key = numbers.public_key(default_backend())
    else:
        raise ValueError('Algorithm not supported!')
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _create_cert(pubkey_pem, subject, valid_days):
    pubkey = load_pem_public_key(pubkey_pem, default_backend())
    dummy_key = ec.generate_private_key(ec.SECP256R1, default_backend())
    today = datetime.datetime.today()

    return x509.CertificateBuilder() \
        .issuer_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject),
        ])) \
        .subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject),
        ])) \
        .public_key(pubkey) \
        .serial_number(struct.unpack('L', os.urandom(8))[0]) \
        .not_valid_before(today - datetime.timedelta(1, 0, 0)) \
        .not_valid_after(today + datetime.timedelta(valid_days, 0, 0)) \
        .sign(dummy_key, hashes.SHA256(), default_backend())


class YkPiv(object):

    def __init__(self, verbosity=0, reader=None):
        self._state = POINTER(ykpiv_state)()
        if not reader:
            reader = 'Yubikey'

        self._key = None
        self._pin = None
        self._pin_blocked = False
        self._verbosity = verbosity
        self._reader = reader
        self._chuid = None
        self._ccc = None
        self._certs = {}

        check(ykpiv.ykpiv_init(byref(self._state), self._verbosity))
        self._connect()
        self._read_status()

    def reconnect(self):
        check(ykpiv.ykpiv_disconnect(self._state))
        self._connect()
        self._read_status()

    def _connect(self):
        check(ykpiv.ykpiv_connect(self._state, self._reader.encode('utf8')))

    def _read_cert_slots(self):
        for slot in CERT_SLOTS:
            der = self.read_cert(slot)
            if der:
                self._certs[slot] = x509.load_der_x509_certificate(
                    der, default_backend())

    def _read_status(self):
        self._read_version()
        self._read_chuid()
        self._read_ccc()
        try:
            self.verify_pin(None)
        except WrongPinError as e:
            self._pin_blocked = e.blocked

        self._read_cert_slots()

    def _read_version(self):
        v = create_string_buffer(10)
        check(ykpiv.ykpiv_get_version(self._state, v, sizeof(v)))
        self._version = v.value

    def _read_chuid(self):
        try:
            chuid_data = self.fetch_object(YKPIV.OBJ.CHUID)[29:29 + 16]
            self._chuid = b2a_hex(chuid_data)
        except PivError:  # No chuid set?
            self._chuid = None

    def _read_ccc(self):
        try:
            ccc_data = self.fetch_object(YKPIV.OBJ.CAPABILITY)[29:29 + 16]
            self._ccc = b2a_hex(ccc_data)
        except PivError:  # No ccc set?
            self._ccc = None

    def __del__(self):
        check(ykpiv.ykpiv_done(self._state))

    @property
    def version(self):
        return self._version

    @property
    def chuid(self):
        return self._chuid

    @property
    def ccc(self):
        return self._ccc

    @property
    def pin_blocked(self):
        return self._pin_blocked

    @property
    def certs(self):
        return dict(self._certs)

    def set_chuid(self):
        chuid = _generate_chuid()
        self.save_object(YKPIV.OBJ.CHUID, chuid)
        self._chuid = chuid

    def set_ccc(self):
        ccc = _generate_ccc()
        self.save_object(YKPIV.OBJ.CAPABILITY, ccc)
        self._ccc = ccc

    def authenticate(self, key=None):
        if key is None:
            key = DEFAULT_KEY
        elif len(key) != KEY_LEN:
            raise ValueError('Key must be %d bytes' % KEY_LEN)
        c_key = (c_ubyte * KEY_LEN).from_buffer_copy(key)
        check(ykpiv.ykpiv_authenticate(self._state, c_key))
        self._key = key
        if not self.chuid:
            self.set_chuid()
        if not self.ccc:
            self.set_ccc()

    def set_authentication(self, key):
        if len(key) != KEY_LEN:
            raise ValueError('Key must be %d bytes' % KEY_LEN)
        c_key = (c_ubyte * len(key)).from_buffer_copy(key)
        check(ykpiv.ykpiv_set_mgmkey(self._state, c_key))
        self._key = key

    def verify_pin(self, pin):
        if isinstance(pin, text_type):
            pin = pin.encode('utf8')
        buf = create_string_buffer(pin) if pin is not None else None
        tries = c_int(-1)
        rc = ykpiv.ykpiv_verify(self._state, buf, byref(tries))

        if rc == YKPIV.WRONG_PIN:
            if tries.value == 0:
                self._pin_blocked = True
            raise WrongPinError(tries.value)
        check(rc)
        self._pin = pin

    def set_pin(self, pin):
        if isinstance(pin, text_type):
            pin = pin.encode('utf8')
        if len(pin) > 8:
            raise ValueError(m.pin_too_long)

        tries = c_int(-1)
        rc = ykpiv.ykpiv_change_pin(self._state, self._pin, len(self._pin),
                                    pin, len(pin), byref(tries))
        if rc in [YKPIV.WRONG_PIN, YKPIV.PIN_LOCKED]:
            raise WrongPukError(tries.value)
        check(rc)
        self._pin = pin

    def reset_pin(self, puk, new_pin):
        if isinstance(new_pin, text_type):
            new_pin = new_pin.encode('utf8')
        if len(new_pin) > 8:
            raise ValueError(m.pin_too_long)
        if isinstance(puk, text_type):
            puk = puk.encode('utf8')

        tries = c_int(-1)
        rc = ykpiv.ykpiv_unblock_pin(self._state, puk, len(puk), new_pin,
                                     len(new_pin), byref(tries))

        if rc in [YKPIV.WRONG_PIN, YKPIV.PIN_LOCKED]:
            raise WrongPukError(tries.value)
        check(rc)
        self._pin = new_pin

    def set_puk(self, puk, new_puk):
        if isinstance(puk, text_type):
            puk = puk.encode('utf8')
        if isinstance(new_puk, text_type):
            new_puk = new_puk.encode('utf8')
        if len(new_puk) > 8:
            raise ValueError(m.puk_too_long)

        tries = c_int(-1)
        rc = ykpiv.ykpiv_change_puk(self._state, puk, len(puk), new_puk,
                                    len(new_puk), byref(tries))
        if rc in [YKPIV.WRONG_PIN, YKPIV.PIN_LOCKED]:
            raise WrongPukError(tries.value)
        check(rc)

    def reset_device(self):
        check(ykpiv.reset(self._state))
        self._key = None
        self._pin = None
        self._read_status()

    def fetch_object(self, object_id):
        buf = (c_ubyte * 4096)()
        buf_len = c_size_t(sizeof(buf))

        check(ykpiv.ykpiv_fetch_object(self._state, object_id, buf,
                                       byref(buf_len)))
        return b''.join(map(int2byte, buf[:buf_len.value]))

    def save_object(self, object_id, data):
        if data is None:
            c_data = None
            d_len = 0
        else:
            c_data = (c_ubyte * len(data)).from_buffer_copy(data)
            d_len = len(data)
        check(ykpiv.ykpiv_save_object(self._state, object_id, c_data, d_len))

    def generate(self, slot, algorithm, pin_policy, touch_policy):
        slot = KEY_SLOTS[slot]
        algorithm = getattr(YKPIV.ALGO, algorithm)
        if not pin_policy:
            pin_policy = 'DEFAULT'
        pin_policy = getattr(YKPIV.PINPOLICY, pin_policy.upper())

        rc, pubkey = ykpiv.generate_key(self._state, slot, algorithm,
                                        pin_policy, touch_policy)

        check(rc)
        return _pubkey_to_pem(algorithm, pubkey)

    def create_csr(self, subject, pubkey_pem, slot):
        try:
            check(ykpiv.ykpiv_disconnect(self._state))
            return self._cmd.create_csr(subject, pubkey_pem, slot)
        finally:
            self._reset()

    def create_selfsigned_cert(self, subject, pubkey_pem, slot, valid_days=365):
        cert = _create_cert(pubkey_pem, subject, valid_days)
        # TODO: Overwrite signature
        data = cert.tbs_certificate_bytes
        digest = sha256(data).digest()
        print(cert.public_bytes(Encoding.PEM).decode('ascii'))
        print('digest:', digest)
        return cert.public_bytes(Encoding.PEM)

    def import_cert(self, cert_pem, slot, frmt='PEM', password=None):
        if frmt == 'PEM':
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        else:
            cert = x509.load_der_x509_certificate(cert_pem, default_backend())
        cert_der = cert.public_bytes(Encoding.DER)
        data = tlv(0x70, cert_der) + tlv(0x71, b'\0') + tlv(0xfe)
        c_data = (c_ubyte * len(data)).from_buffer_copy(data)
        d_len = len(data)
        check(ykpiv.ykpiv_save_object(self._state, CERT_SLOTS[slot], c_data,
                                      d_len))
        self._read_cert_slots()

    def import_key(self, cert_pem, slot, frmt, password, pin_policy,
                   touch_policy):
        try:
            check(ykpiv.ykpiv_disconnect(self._state))
            return self._cmd.import_key(cert_pem, slot, frmt, password,
                                        pin_policy, touch_policy)
        finally:
            self._reset()

    def sign_data(self, slot, hashed, algorithm=YKPIV.ALGO.RSA2048):
        c_hashed = (c_ubyte * len(hashed)).from_buffer_copy(hashed)
        buf = (c_ubyte * 4096)()
        buf_len = c_size_t(sizeof(buf))
        check(ykpiv.ykpiv_sign_data(self._state, c_hashed, len(hashed), buf,
                                    byref(buf_len), algorithm, int(slot, 16)))
        return ''.join(map(int2byte, buf[:buf_len.value]))

    def read_cert(self, slot):
        try:
            data = self.fetch_object(CERT_SLOTS[slot])
        except PivError:
            return None
        cert, rest = der_read(data, 0x70)
        zipped, rest = der_read(rest, 0x71)
        if zipped != b'\0':
            pass  # TODO: cert is compressed, uncompress.
        return cert

    def delete_cert(self, slot):
        if slot not in self._certs:
            raise ValueError('No certificate loaded in slot: %s' % slot)

        self.save_object(CERT_SLOTS[slot], None)
        del self._certs[slot]
