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

from pivman.libykpiv import YKPIV
from pivman.piv_cmd import YkPivCmd
from pivman import messages as m
from pivman.utils import der_read
from pivman.yubicommon.compat import text_type
from binascii import a2b_hex, b2a_hex
import re


_YKPIV_MIN_VERSION = b'1.2.0'


class DeviceGoneError(Exception):

    def __init__(self):
        super(DeviceGoneError, self).__init__(m.communication_error)


PIV_ERRORS = {
    YKPIV.OK: "Successful return",
    YKPIV.MEMORY_ERROR: "Error allocating memory",
    YKPIV.PCSC_ERROR: "Error in PCSC call",
    YKPIV.SIZE_ERROR: "Wrong buffer size",
    YKPIV.APPLET_ERROR: "No PIV application found",
    YKPIV.AUTHENTICATION_ERROR: "Error during authentication",
    YKPIV.RANDOMNESS_ERROR: "Error getting randomness",
    YKPIV.GENERIC_ERROR: "Something went wrong.",
    YKPIV.KEY_ERROR: "Error in key",
    YKPIV.PARSE_ERROR: "Parse error",
    YKPIV.WRONG_PIN: "Wrong PIN code",
    YKPIV.INVALID_OBJECT: "Object invalid",
    YKPIV.ALGORITHM_ERROR: "Algorithm error"
}


class PivError(Exception):
    def __init__(self, code):
        message = PIV_ERRORS[code]
        super(PivError, self).__init__(code, message)
        self.code = code
        self.message = message

    def __str__(self):
        return m.ykpiv.ykpiv_error_2 % (self.code, self.message)


class WrongPinError(ValueError):
    m_tries_1 = m.wrong_pin_tries_1
    m_blocked = m.pin_blocked

    def __init__(self, tries):
        super(WrongPinError, self).__init__(self.m_tries_1 % tries
                                            if tries > 0 else self.m_blocked)
        self.tries = tries

    @property
    def blocked(self):
        return self.tries == 0


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

CERT_SLOTS = {
    '9a': YKPIV.OBJ.AUTHENTICATION,
    '9c': YKPIV.OBJ.SIGNATURE,
    '9d': YKPIV.OBJ.KEY_MANAGEMENT,
    '9e': YKPIV.OBJ.CARD_AUTH
}

ATTR_NAME = 'name'

TRIES_PATTERN = re.compile(r'now (\d+) tries')

libversion = YkPivCmd().tool_version()


class YkPiv(object):

    def __init__(self, verbosity=0, reader=None):
        self._cmd = YkPivCmd(verbosity=verbosity, reader=reader)

        v_tuple = tuple(int(x) for x in libversion.split(b'.'))
        if v_tuple < (1, 4, 0):
            raise ValueError('yubico-piv-tool >= 1.4.0 required!')

        if not reader:
            reader = 'Yubikey'

        self._chuid = None
        self._ccc = None
        self._pin_blocked = False
        self._verbosity = verbosity
        self._reader = reader
        self._certs = {}

        self._read_status()

        if not self.chuid:
            try:
                self.set_chuid()
            except ValueError:
                pass  # Not autheniticated, perhaps?

        if not self.ccc:
            try:
                self.set_ccc()
            except ValueError:
                pass  # Not autheniticated, perhaps?

    def reconnect(self):
        pass

    def _read_status(self):
        data = self._cmd.status()
        lines = data.splitlines()
        chunk = []
        while lines:
            line = lines.pop(0)
            if chunk and not line.startswith(b'\t'):
                self._parse_status(chunk)
                chunk = []
            chunk.append(line)
        if chunk:
            self._parse_status(chunk)
        self._status = data

    def _parse_status(self, chunk):
        parts, rest = chunk[0].split(), chunk[1:]
        if parts[0] == b'Slot' and rest:
            self._parse_slot(parts[1][:-1], rest)
        elif parts[0] == b'PIN':
            self._pin_blocked = parts[-1] == b'0'
        elif parts[0] == b'CHUID:':
            if len(parts[1:]) == 1:
                self._chuid = parts[1]
        elif parts[0] == b'CCC:':
            if len(parts[1:]) == 1:
                self._ccc = parts[1]

    def _parse_slot(self, slot, lines):
        slot = slot.decode('ascii')
        self._certs[slot] = dict(l.strip().split(b':\t', 1) for l in lines)

    def _read_version(self):
        self._version = self._cmd.version()

    def _reset(self):
        self._connect()
        args = self._cmd._base_args
        if '-P' in args:
            self.verify_pin(args[args.index('-P') + 1])
        if '-k' in args:
            self.authenticate(a2b_hex(args[args.index('-k') + 1]))

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
        self._cmd.run('-a', 'set-chuid')

    def set_ccc(self):
        self._cmd.run('-a', 'set-ccc')

    def authenticate(self, key=None):
        if key is None:
            key = DEFAULT_KEY
        elif len(key) != KEY_LEN:
            raise ValueError('Key must be %d bytes' % KEY_LEN)
        self._cmd.set_arg('-k', b2a_hex(key))
        try:
            # Verifies that the key is correct
            self._cmd.set_mgm_key(b2a_hex(key))
        except:
            raise PivError(YKPIV.AUTHENTICATION_ERROR)
        if not self.chuid:
            self.set_chuid()
        if not self.ccc:
            self.set_ccc()

    def set_authentication(self, key):
        if len(key) != KEY_LEN:
            raise ValueError('Key must be %d bytes' % KEY_LEN)
        self._cmd.set_mgm_key(b2a_hex(key))

    def verify_pin(self, pin):
        if isinstance(pin, text_type):
            pin = pin.encode('utf8')
        try:
            self._cmd.run('-a', 'verify', '-P', pin)
            self._cmd.set_arg('-P', pin)
        except ValueError as e:
            m = re.search(r' (\d+) tries', str(e))
            if m:
                raise WrongPinError(int(m.group(1)))
            else:
                self._pin_blocked = True
                raise WrongPinError(0)

    def set_pin(self, pin):
        if isinstance(pin, text_type):
            pin = pin.encode('utf8')
        if len(pin) > 8:
            raise ValueError(m.pin_too_long)
        self._cmd.change_pin(pin)

    def reset_pin(self, puk, new_pin):
        if isinstance(new_pin, text_type):
            new_pin = new_pin.encode('utf8')
        if len(new_pin) > 8:
            raise ValueError(m.pin_too_long)
        if isinstance(puk, text_type):
            puk = puk.encode('utf8')
        try:
            self._cmd.reset_pin(puk, new_pin)
        except ValueError as e:
            wrap_puk_error(e)
        finally:
            self._read_status()

    def set_puk(self, puk, new_puk):
        if isinstance(puk, text_type):
            puk = puk.encode('utf8')
        if isinstance(new_puk, text_type):
            new_puk = new_puk.encode('utf8')
        if len(new_puk) > 8:
            raise ValueError(m.puk_too_long)

        try:
            self._cmd.change_puk(puk, new_puk)
        except ValueError as e:
            wrap_puk_error(e)

    def reset_device(self):
        try:
            self._cmd.run('-a', 'reset')
        finally:
            del self._cmd

    def fetch_object(self, object_id):
        try:
            return self._cmd.read_object(object_id)
        except:
            raise PivError(YKPIV.INVALID_OBJECT)

    def save_object(self, object_id, data):
        self._cmd.write_object(object_id, data)

    def generate(self, slot, algorithm, pin_policy, touch_policy):
        return self._cmd.generate(slot, algorithm, pin_policy, touch_policy)

    def create_csr(self, subject, pubkey_pem, slot):
        return self._cmd.create_csr(subject, pubkey_pem, slot)

    def create_selfsigned_cert(self, subject, pubkey_pem, slot, valid_days=365):
        return self._cmd.create_ssc(subject, pubkey_pem, slot, valid_days)

    def import_cert(self, cert_pem, slot, frmt='PEM', password=None):
        self._cmd.import_cert(cert_pem, slot, frmt, password)
        self._read_status()

    def import_key(self, cert_pem, slot, frmt, password, pin_policy,
                   touch_policy):
        return self._cmd.import_key(cert_pem, slot, frmt, password,
                                    pin_policy, touch_policy)

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

        self._cmd.delete_cert(slot)
        del self._certs[slot]
        self._read_status()
