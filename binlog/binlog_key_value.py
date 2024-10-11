from typing import Self

from binlog.tl_parser import TlParser


# https://github.com/tdlib/td/blob/97ded01095246a3a693bc85bef4bca5d1af177dd/tddb/td/db/BinlogKeyValue.h#L37
class BinlogKeyValue(dict):
    # https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/BinlogKeyValue.h#L41
    class StorageEvent:
        def __init__(self, key: str, value: bytes) -> None:
            self.key = key
            self.value = value

        # https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/BinlogKeyValue.h#L54
        @classmethod
        def parse(cls, parser: TlParser) -> Self:
            key = parser.read_string()
            value = parser.read_bytes()  # read_bytes() instead of read_string()
            return cls(key, value)
