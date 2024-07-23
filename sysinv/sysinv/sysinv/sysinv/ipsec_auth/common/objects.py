#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import binascii
import enum
import random
import secrets
import string
import time
import threading

from oslo_log import log as logging
from sysinv.ipsec_auth.common import constants

LOG = logging.getLogger(__name__)


class StatusCode(enum.Enum):
    IPSEC_OP_SUCCESS = "10"
    IPSEC_OP_ENABLED = "11"
    IPSEC_OP_FAILURE_GENERAL = "20"
    IPSEC_OP_IN_PROGRESS = "30"


class State(enum.Enum):
    STAGE_1 = 1
    STAGE_2 = 2
    STAGE_3 = 3
    STAGE_4 = 4
    END_STAGE = 5

    @staticmethod
    def get_next_state(state, op):
        '''Get the next IPsec Auth state whenever a Stage is finished.

        The IPsec Auth server-client interaction is separated into 5 work stages.
        STAGE_1:   represents the initial stage where IPsec Auth client send
                   the first message with OP code, mac address and a hash to
                   IPsec Auth server.
        STAGE_2:   represents the stage of validation of the message 1 received
                   from the client and generation of a response message. If the
                   validation is satisfied, the IPsec Auth server will encapsulate
                   an OTS Token, client's hostname, generated public key,
                   system-local-ca's certificate and a signed hash of this payload
                   in the response message to send it to the client.
        STAGE_3:   represents the stage of validation of the message 2 received
                   from the server and generation of a response message. if the
                   validation is satisfied, the IPsec Auth Client will encapsulate
                   an OTS Token, an encrypted Initial Vector (eiv), an encrypted
                   symetric key (eak1), an encrypted certificate request (eCSR)
                   and a signed hash of this payload in the response message to
                   send it to the server.
        STAGE_4:   represents the stage of validation of the message 3 from the
                   client and generation of a final response message. If the
                   validation of the message is satisfied, the IPsec Auth server
                   will create a CertificateRequest resource with a CSR received
                   from client's message and will encapsulate the signed
                   Certificate, network info and a signed hash of this payload in
                   the response message to send it to the client.
        END_STAGE: represents the final stage of IPsec PKI Auth procedure and demands
                   that IPsec Auth server and client close the connection that
                   finished STAGE_4.
        '''

        if op == constants.OP_CODE_CERT_VALIDATION:
            if state == State.STAGE_1:
                state = State.STAGE_2
            elif state == State.STAGE_2:
                state = State.END_STAGE
        else:
            if state == State.STAGE_1:
                state = State.STAGE_2
            elif state == State.STAGE_2:
                state = State.STAGE_3
            elif state == State.STAGE_3:
                state = State.STAGE_4
            elif state == State.STAGE_4:
                state = State.END_STAGE

        return state


class Token(object):
    VERSION = int(1).to_bytes(1, 'little')
    EXPIRY_TIME = 7000

    def __init__(self):
        self.__nonce = secrets.token_bytes(16)  # 128-bit nonce
        self.__creation_time = int(time.time() * 1000)  # 64-bit utc time
        self.__content = bytearray(self.VERSION + self.__nonce
                                   + self.__creation_time.to_bytes(8, 'little'))
        self.__used = False
        self.__expired = False
        self.__start_time = 0
        self.__timer = None

        random.shuffle(self.__content)

    def __repr__(self):
        return binascii.hexlify(self.__content).decode("utf-8")

    def __set_timer(self):
        interval = self.EXPIRY_TIME / 1000
        timer = threading.Timer(interval, self.__expire_token)
        timer.start()
        return timer

    def __expire_token(self):
        self.__expired = True
        if self.__timer and self.__timer.is_alive():
            self.__timer.cancel()
            LOG.info("OTS Token set as expired")
        else:
            LOG.info("OTS Token expired")
        return None

    def activate(self):
        '''Activate OTS Token timer.'''
        self.__start_time = int(time.time() * 1000)
        self.__timer = self.__set_timer()
        LOG.info("OTS Token activated")
        return None

    def purge(self):
        '''Purge the token.'''
        self.__used = True
        self.__content = bytearray()
        self.__expire_token()
        LOG.info("OTS Token purged")
        return None

    def set_as_used(self):
        '''Set token as used.'''
        self.__used = True
        LOG.info("OTS Token set as used")
        return None

    def get_content(self):
        '''Returns token's content value.'''
        return self.__content

    def is_valid(self) -> bool:
        '''Verifies if token is valid per the evaluation of the expiration
        time and its usage flag.'''
        period = int(time.time() * 1000) - self.__start_time
        if period >= self.EXPIRY_TIME and not self.__expired:
            self.__expire_token()

        return not (self.__expired or self.__used)

    def compare_tokens(self, token: str) -> bool:
        '''Compares token's hex value with a hex string.'''
        if len(token) > 0 and all(char in string.hexdigits for char in token):
            return (repr(self) == token)
        return False
