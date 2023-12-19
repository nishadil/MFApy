import struct
import base64
import hashlib
import os
import time

class Mfa:
    mfa_TOTPLength = 6
    mfa_secretCodeLength = 16
    mfa_secretCodeTime = 30
    mfa_decodeSecretCodeValidValues = [6, 4, 3, 1, 0]

    @staticmethod
    def create_secret_code():
        base32_lookup_table = Mfa.base32_lookup_table()
        create_random_bytes = Mfa.create_random_bytes()

        if not create_random_bytes:
            raise Exception("Nishadil\MFA : Failed to create random bytes")

        secret_code = ''.join(base32_lookup_table[b & 31] for b in create_random_bytes)

        return secret_code

    @staticmethod
    def get_totp(secret_code):
        mfa_time = int(time.time()) // Mfa.mfa_secretCodeTime
        secret_code_decoded = Mfa.decode_secret_code(secret_code)

        if not secret_code_decoded:
            return ''

        binary_time = struct.pack('>Q', mfa_time)
        hm = Mfa.hmac_sha1(secret_code_decoded, binary_time)
        offset = hm[-1] & 0x0F
        hash_part = hm[offset:offset + 4]
        value = struct.unpack('>I', hash_part)[0] & 0x7FFFFFFF

        return str(value % (10 ** Mfa.mfa_TOTPLength)).zfill(Mfa.mfa_TOTPLength)

    @staticmethod
    def get_hotp(secret_code, counter):
        secret_code_decoded = Mfa.decode_secret_code(secret_code)

        if not secret_code_decoded:
            return ''

        counter_bytes = struct.pack('>Q', counter)
        hm = Mfa.hmac_sha1(secret_code_decoded, counter_bytes)
        offset = hm[-1] & 0x0F
        hash_part = hm[offset:offset + 4]
        value = struct.unpack('>I', hash_part)[0] & 0x7FFFFFFF

        return str(value % (10 ** Mfa.mfa_TOTPLength)).zfill(Mfa.mfa_TOTPLength)

    @staticmethod
    def set_secret_code_length(secret_code_length=None):
        if secret_code_length is None or secret_code_length < 16 or secret_code_length > 128:
            secret_code_length = 16

        Mfa.mfa_secretCodeLength = secret_code_length

    @staticmethod
    def create_random_bytes():
        try:
            return os.urandom(Mfa.mfa_secretCodeLength)
        except Exception as e:
            return None

    @staticmethod
    def decode_secret_code(secret_code):
        if not secret_code:
            return None

        base32_lookup_table = Mfa.base32_lookup_table()
        base32_lookup_table_flip = {v: k for k, v in enumerate(base32_lookup_table)}

        sub_str_count = secret_code.count(base32_lookup_table[32])

        if sub_str_count not in Mfa.mfa_decodeSecretCodeValidValues:
            return None

        for i in range(4):
            if (sub_str_count == Mfa.mfa_decodeSecretCodeValidValues[i] and
                    secret_code[-Mfa.mfa_decodeSecretCodeValidValues[i]:] !=
                    base32_lookup_table[32] * Mfa.mfa_decodeSecretCodeValidValues[i]):
                return None

        secret_code = secret_code.replace('=', '')
        secret_code_decoded = b''

        for i in range(0, len(secret_code), 8):
            x = ''
            if secret_code[i] not in base32_lookup_table:
                return None

            for n in range(8):
                x += format(base32_lookup_table_flip.get(secret_code[i + n], 0), '05b')

            mfa_eight_bits = [x[j:j + 8] for j in range(0, len(x), 8)]
            for d in range(len(mfa_eight_bits)):
                secret_code_decoded += bytes([int(mfa_eight_bits[d], 2)])

        return secret_code_decoded

    @staticmethod
    def hmac_sha1(key, data):
        if len(key) > 64:
            key = hashlib.sha1(key).digest()
        key = key.ljust(64, b'\0')
        o_key_pad = bytes((x ^ 0x5C) for x in key)
        i_key_pad = bytes((x ^ 0x36) for x in key)
        inner_hash = hashlib.sha1(i_key_pad + data).digest()
        return hashlib.sha1(o_key_pad + inner_hash).digest()

    @staticmethod
    def base32_lookup_table():
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', '2', '3', '4', '5', '6', '7',
            '='
        ]

