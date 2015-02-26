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

from pivtool.utils import complexity_check, test
from pivtool.piv import PivError
from pivtool import messages as m
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from getpass import getuser
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459
from datetime import datetime, timedelta
import os
import tempfile
import time
import struct
import subprocess


YKPIV_OBJ_PIN_TIMESTAMP = 0x5fff00
YKPIV_OBJ_PIN_SALT = 0x5fff01


def derive_key(password, salt):
    if isinstance(password, unicode):
        password = password.encode('utf8')
    return PBKDF2(password, salt, 24, 10000)


def request_cert_from_ca(csr):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(csr)
            csr_fn = f.name

        with tempfile.NamedTemporaryFile() as f:
            cert_fn = f.name

        p = subprocess.Popen(['certreq', '-submit', '-attrib',
                              'CertificateTemplate:User', csr_fn, cert_fn],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()

        with open(cert_fn, 'r') as cert:
            return cert.read()
    except OSError as e:
        raise ValueError(m.certreq_error_1 % e)
    finally:
        os.remove(csr_fn)
        if os.path.isfile(cert_fn):
            os.remove(cert_fn)


class Controller(object):

    def __init__(self, key):
        self._key = key
        try:
            self._salt = self._key.fetch_object(YKPIV_OBJ_PIN_SALT)
        except PivError:
            self._salt = ''

    def _authenticate(self, pin=None):
        if test(self._key.authenticate, catches=PivError):  # Default key
            return

        if pin is not None:
            if test(self._key.authenticate, derive_key(pin, self._salt),
                    catches=PivError):  # Key derived from PIN
                return

        password = None  # TODO: Ask for password
        if password is None:
            raise ValueError(m.authentication_error)
        self._key.authenticate(derive_key(password, self._salt))

    def is_uninitialized(self):
        return test(self._key.authenticate)

    def initialize(self, pin, old_pin='123456'):
        self.change_pin(old_pin, pin)
        for i in range(3):  # Invalidate the PUK
            test(self._key.set_puk, '', '', catches=ValueError)

    def change_pin(self, old_pin, new_pin):
        if not complexity_check(new_pin):
            raise ValueError(m.pin_not_complex)
        self._key.verify_pin(old_pin)
        self._authenticate(old_pin)
        self._key.set_pin(new_pin)

        salt = get_random_bytes(16)
        new_key = derive_key(new_pin, salt)
        self._key.set_authentication(new_key)
        self._key.save_object(YKPIV_OBJ_PIN_SALT, salt)
        self._salt = salt

        timestamp = struct.pack('i', int(time.time()))
        self._key.save_object(YKPIV_OBJ_PIN_TIMESTAMP, timestamp)

    def request_certificate(self, pin):
        self._key.verify_pin(pin)
        self._authenticate(pin)
        pubkey = self._key.generate()
        subject = '/CN=%s/' % getuser()
        csr = self._key.create_csr(subject, pubkey)
        cert = request_cert_from_ca(csr)
        self._key.import_cert(cert)
        self._key.set_chuid()

    def get_pin_last_changed(self):
        try:
            data = self._key.fetch_object(YKPIV_OBJ_PIN_TIMESTAMP)
            return struct.unpack('i', data)[0]
        except PivError:
            return None

    def is_pin_expired(self):
        last_changed = self.get_pin_last_changed()
        if last_changed is None:
            return True
        delta = timedelta(seconds=time.time() - last_changed)
        return delta.days > 30

    def get_certificate_expiration(self):
        cert = self._key.read_cert()
        if cert is None:
            return None
        if cert[0] == chr(0x70):  # TODO: Is this always 0x70?
            cert = cert[4:]
        cert = decoder.decode(cert, asn1Spec=rfc2459.Certificate())[0]
        expiration = cert['tbsCertificate']['validity']['notAfter']
        value = expiration.getComponentByName(expiration.getName()).asOctets()
        if expiration.getName() == 'utcTime':
            if int(value[0:2]) < 50:
                value = '20' + value
            else:
                value = '19' + value
        if value.endswith('Z'):
            value = value[:-1]
        else:
            # TODO: +/-hhmm
            pass
        dt = datetime.strptime(value + 'GMT', '%Y%m%d%H%M%S%Z')
        return int((dt - datetime.fromtimestamp(0)).total_seconds())

    def is_cert_expired(self):
        expiry = self.get_certificate_expiration()
        if expiry is None:
            return True
        else:
            return time.time() > expiry
