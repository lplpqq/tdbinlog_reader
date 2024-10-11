class BinlogException(Exception):
    def __init__(self, message: str) -> None:
        self.message = message


class InvalidPassword(BinlogException):
    """Invalid password when trying to encrypt (kinda decrypt) binlog"""


class BinlogEventInvalid(BinlogException):
    """Binlog event is invalid"""


class BinlogEventSizeInvalid(BinlogEventInvalid):
    """Binlog event size invalid"""


class BinlogEventCrc32HashInvalid(BinlogEventInvalid):
    """Binlog crc32 hash invalid"""
