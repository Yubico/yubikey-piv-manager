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

from pivtool.utils import derive_key, complexity_check
import time
import struct


YKPIV_OBJ_PIN_TIMESTAMP = 0x5fff00


def request_cert_from_ca(csr):
    return None  # TODO: Call certreq


class Controller(object):

    def __init__(self, key):
        self._key = key

    def _authenticate(self, pin=None):
        try:  # Default key
            self._key.authenticate()
            return
        except ValueError:
            pass

        if pin is not None:
            try:  # Key derived from PIN
                self._key.authenticate(derive_key(pin))
                return
            except ValueError:
                pass

        password = None  # TODO: Ask for password
        if password is None:
            raise ValueError('Unable to authenticate')
        self._key.authenticate(derive_key(password))

    def change_pin(self, old_pin, new_pin):
        if not complexity_check(new_pin):
            raise ValueError('New PIN does not meet complexity rules')
        self._key.verify_pin(old_pin)
        self._authenticate(old_pin)
        new_key = derive_key(new_pin)
        self._key.set_pin(new_pin)
        self._key.set_authentication(new_key)

        timestamp = struct.pack('i', int(time.time()))
        self._key.save_object(YKPIV_OBJ_PIN_TIMESTAMP, timestamp)

    def request_certificate(self, pin):
        self._key.verify_pin(pin)
        self._authenticate(pin)
        pubkey = self._key.generate()
        subject = '/CN=example/O=test/'  # TODO: Insert username
        csr = self._key.create_csr(subject, pubkey)
        cert = request_cert_from_ca(csr)
        self._key.import_cert(cert)
        self._key.set_chuid()

    def get_pin_last_changed(self):
        try:
            data = self._key.fetch_object(YKPIV_OBJ_PIN_TIMESTAMP)
            return struct.unpack('i', data)[0]
        except ValueError:
            return None

    def get_certificate_expiration(self):
        # TODO: read certificate
        # TODO: if exists, parse ASN1, get expiration.
        pass
