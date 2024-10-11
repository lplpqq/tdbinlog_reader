import hashlib
import hmac
from hashlib import pbkdf2_hmac
from typing import Self

from binlog.tl_parser import TlParser


# https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/Binlog.cpp#L31
class AesCtrEncryptionEvent:
    MIN_SALT_SIZE = 16  # it isn't used
    DEFAULT_SALT_SIZE = 32  # it isn't used
    KEY_SIZE = 32
    IV_SIZE = 16  # it isn't used
    HASH_SIZE = 32  # it isn't used
    KDF_ITERATION_COUNT = 60002  # it isn't used
    KDF_FAST_ITERATION_COUNT = 2

    def __init__(self, key_salt: bytes, iv: bytes, key_hash: bytes) -> None:
        self.key_salt = key_salt
        self.iv = iv
        self.key_hash = key_hash

    def generate_key(self, db_key: str) -> bytes:
        # we use KDF_FAST_ITERATION_COUNT, because we will only use raw_key
        # see: https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/Binlog.cpp#L62
        return pbkdf2_hmac(
            'sha256', db_key.encode(), self.key_salt, self.KDF_FAST_ITERATION_COUNT,
            dklen=self.KEY_SIZE
        )

    @staticmethod
    def generate_hash(key) -> bytes:
        return hmac.new(key, b'cucumbers everywhere', hashlib.sha256).digest()

    @classmethod
    def parse(cls, parser: TlParser) -> Self:
        # https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/Binlog.cpp#L87
        parser.seek(4)  # BEGIN_PARSE_FLAGS function consumes 4 bytes, because of read_int()

        key_salt = parser.read_bytes()  # KEY_SIZE = 32
        iv = parser.read_bytes()  # IV_SIZE = 16
        key_hash = parser.read_bytes()  # HASH_SIZE = 16

        return cls(key_salt, iv, key_hash)
