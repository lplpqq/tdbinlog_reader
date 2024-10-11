import os
from io import BytesIO
from struct import unpack


# https://github.com/tdlib/td/blob/master/tdutils/td/utils/tl_parsers.h#L24
class TlParser:
    def __init__(self, buffer: bytes | bytearray) -> None:
        self.stream = BytesIO(buffer)

    # region custom Reading
    def read_byte(self) -> int:
        """Reads a single byte value."""
        return self.read(1)[0]

    def read_int(self, signed=True) -> int:
        """Reads an integer (4 bytes) value."""
        return int.from_bytes(self.read(4), byteorder='little', signed=signed)

    def read_long(self, signed=True) -> int:
        """Reads a long integer (8 bytes) value."""
        return int.from_bytes(self.read(8), byteorder='little', signed=signed)

    def read_double(self) -> float:
        """Reads a real floating point (8 bytes) value."""
        return unpack('<d', self.read(8))[0]

    def read(self, length=-1) -> bytes:
        """Read the given number of bytes, or -1 to read all remaining."""
        result = self.stream.read(length)
        if (length >= 0) and (len(result) != length):
            raise BufferError(
                'No more data left to read (need {}, got {}: {});'
                .format(length, len(result), repr(result))
            )

        return result

    def read_bytes(self) -> bytes:
        first_byte = self.read_byte()
        if first_byte == 254:
            length = self.read_byte() | (self.read_byte() << 8) | (
                self.read_byte() << 16)
            padding = length % 4
        else:
            length = first_byte
            padding = (length + 1) % 4

        data = self.read(length)
        if padding > 0:
            padding = 4 - padding
            self.read(padding)

        return data

    def read_string(self) -> str:
        return str(self.read_bytes(), encoding='utf-8', errors='replace')

    # endregion

    # region BytesIO related

    def get_value(self) -> bytes:
        return self.stream.getvalue()

    def seek(self, offset: int) -> None:
        self.stream.seek(offset, os.SEEK_CUR)

    # endregion
