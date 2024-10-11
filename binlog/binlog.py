from typing import Optional

from tgcrypto import ctr256_encrypt

from binlog.binlog_event import BinlogEvent
from binlog.binlog_key_value import BinlogKeyValue
from binlog.events import AesCtrEncryptionEvent
from binlog.exceptions import InvalidPassword, BinlogEventSizeInvalid
from binlog.handler import HandlerType
from binlog.tl_parser import TlParser

# https://github.com/tdlib/td/blob/97ded01095246a3a693bc85bef4bca5d1af177dd/td/telegram/Td.cpp#L2770
DEFAULT_DB_KEY = "cucumber"


# https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/Binlog.cpp#L95
class Binlog:
    def __init__(self, buffer: bytes | bytearray, password: Optional[str] = None) -> None:
        self._parser = TlParser(buffer)
        self._password = password or DEFAULT_DB_KEY
        self.map = BinlogKeyValue()

    # https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/Binlog.cpp#L112
    def read_next_event(self) -> BinlogEvent:
        size = self._parser.read_int()
        self._parser.seek(-4)  # go back

        if size > BinlogEvent.MAX_SIZE:
            raise BinlogEventSizeInvalid(f'Event is too big: {size}')
        elif size < BinlogEvent.MIN_SIZE:
            raise BinlogEventSizeInvalid(f'Event is too small: {size}')
        elif size % 4 != 0:
            raise BinlogEventSizeInvalid(f'Event size is not expected: {size}')

        return BinlogEvent.parse(TlParser(self._parser.read(size)))

    # https://github.com/tdlib/td/blob/cb164927417f22811c74cd8678ed4a5ab7cb80ba/tddb/td/db/binlog/Binlog.cpp#L326
    def process_event(self, event: BinlogEvent) -> None:
        if event.type == BinlogEvent.ServiceTypes.AesCtrEncryption.value:
            aes_encryption_event = AesCtrEncryptionEvent.parse(TlParser(event.event_data))
            secret_key = aes_encryption_event.generate_key(self._password)

            if aes_encryption_event.generate_hash(secret_key) != aes_encryption_event.key_hash:
                raise InvalidPassword(f"Password is invalid. "
                                      f"Generated hash={aes_encryption_event.generate_hash(secret_key)}, "
                                      f"real hash={aes_encryption_event.key_hash}")

            data = self._parser.read()
            # https://github.com/tdlib/td/blob/81dc2e242b6c3ea358dba6b5a750727c378dc098/tddb/td/db/binlog/Binlog.cpp#L472
            decrypted_buffer = ctr256_encrypt(data, secret_key, aes_encryption_event.iv, bytes(1))

            # https://github.com/tdlib/td/blob/81dc2e242b6c3ea358dba6b5a750727c378dc098/tddb/td/db/binlog/Binlog.cpp#L478
            self._parser = TlParser(decrypted_buffer)

        # we only process these events
        # https://github.com/tdlib/td/blob/81dc2e242b6c3ea358dba6b5a750727c378dc098/td/telegram/TdDb.cpp#L161
        # https://github.com/tdlib/td/blob/81dc2e242b6c3ea358dba6b5a750727c378dc098/td/telegram/TdDb.cpp#L164
        # also see binlog dump script:
        # https://github.com/tdlib/td/blob/81dc2e242b6c3ea358dba6b5a750727c378dc098/tddb/td/db/binlog/binlog_dump.cpp#L127
        elif event.type in [HandlerType.ConfigPmcMagic.value, HandlerType.BinlogPmcMagic.value]:
            storage_event = BinlogKeyValue.StorageEvent.parse(TlParser(event.event_data))

            self.map[storage_event.key] = storage_event.value
