import time
from typing import Self

from binlog.tl_parser import TlParser


# https://github.com/tdlib/td/blob/d7203eb719304866a7eb7033ef03d421459335b8/td/mtproto/AuthKey.h#L126
class AuthKey:
    AUTH_FLAG = 1
    HAS_CREATED_AT = 4
    HAS_EXPIRES_AT = 8

    def __init__(self, auth_key: bytes,
                 auth_key_id: int = 0,
                 auth_flag: bool = False, have_header: bool = True, header_expires_at: int = 0,
                 expires_at: int = 0, created_at: int = 0) -> None:
        self.auth_key = auth_key

        self.auth_key_id = auth_key_id
        self.auth_flag = auth_flag
        self.have_header = have_header
        self.header_expires_at = header_expires_at

        self.expires_at = expires_at
        self.created_at = created_at

    # https://github.com/tdlib/td/blob/d7203eb719304866a7eb7033ef03d421459335b8/td/mtproto/AuthKey.h#L104
    @classmethod
    def parse(cls, parser: TlParser) -> Self:
        auth_key_id = parser.read_long(signed=False)
        flags = parser.read_int()
        auth_flag = bool(flags & cls.AUTH_FLAG)
        auth_key = parser.read_bytes()

        created_at = 0
        if flags & cls.HAS_CREATED_AT:
            created_at = int(parser.read_double())

        expires_at = 0
        if flags & cls.HAS_EXPIRES_AT:
            time_left = parser.read_double()
            old_server_time = parser.read_double()
            passed_server_time = max(time.time() - old_server_time, 0.0)
            time_left = max(time_left - passed_server_time, 0.0)
            expires_at = int(time.time() + time_left)

        return cls(
            auth_key, auth_key_id, auth_flag, True, expires_at=expires_at, created_at=created_at
        )
