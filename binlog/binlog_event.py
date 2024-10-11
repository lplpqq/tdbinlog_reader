import zlib
from enum import IntEnum
from typing import Self

from binlog.exceptions import BinlogEventSizeInvalid, BinlogEventCrc32HashInvalid
from binlog.tl_parser import TlParser


# https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/BinlogEvent.h#L50
class BinlogEvent:
    MAX_SIZE = 1 << 24
    HEADER_SIZE = 4 + 8 + 4 + 4 + 8
    TAIL_SIZE = 4
    MIN_SIZE = HEADER_SIZE + TAIL_SIZE

    class ServiceTypes(IntEnum):
        Header = -1
        Empty = -2
        AesCtrEncryption = -3
        NoEncryption = -4  # is not used at all

    def __init__(self, raw_event: bytes,
                 event_data: bytes,
                 size: int, id_: int, type_: int, flags: int, extra: int, crc32: int) -> None:
        self.raw_event = raw_event
        self.event_data = event_data
        self.size = size
        self.id = id_
        self.type = type_
        self.flags = flags
        self.extra = extra
        self.crc32 = crc32

    # https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/BinlogEvent.cpp#L17
    @classmethod
    def parse(cls, parser: TlParser) -> Self:
        size = parser.read_int(False)  # cast into uint32: 4 bytes
        id_ = parser.read_long(False)  # cast into uint64: 8 bytes
        type_ = parser.read_int(True)  # no cast: 4 bytes
        flags = parser.read_int(True)  # no cast: 4 bytes
        extra = parser.read_long(False)  # cast into uint64: 8 bytes

        # in original code it says "skip data". this was implemented, so inside method `get_data`
        # this content aka event_data would be read and returned. but we do it already in place
        # https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/BinlogEvent.cpp#L26
        # https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/BinlogEvent.cpp#L33
        # HEADER_SIZE = sum bytes of: size + id_ + type_ + flags + extra
        event_data = parser.read(size - cls.MIN_SIZE)

        crc32 = parser.read_int(False)  # cast into uint32: 4 bytes

        return cls(parser.get_value(), event_data, size, id_, type_, flags, extra, crc32)

    def validate(self) -> None:
        if len(self.raw_event) < self.MIN_SIZE:
            raise BinlogEventSizeInvalid(f'Event is too small: {len(self.raw_event)}')

        expected_binlog_event = BinlogEvent.parse(TlParser(self.raw_event))
        if self.size != expected_binlog_event.size or self.size != len(self.raw_event):
            raise BinlogEventSizeInvalid(f'Size of event changed: was={self.size}, now={expected_binlog_event.size}, '
                                         f'real_size={len(self.raw_event)}')

        data = self.raw_event[:-self.TAIL_SIZE]
        calculated_crc = zlib.crc32(data)
        stored_crc = expected_binlog_event.crc32

        if calculated_crc != self.crc32 or calculated_crc != stored_crc:
            raise BinlogEventCrc32HashInvalid(f'CRC32 hash mismatch: actual={calculated_crc}, expected={self.crc32}')
