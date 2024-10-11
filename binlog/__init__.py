import os
from typing import BinaryIO, Optional

from binlog.binlog import Binlog


def read(tdbinlog_file: str | os.PathLike | BinaryIO, password: Optional[str] = None) -> Binlog:
    if isinstance(tdbinlog_file, (str, os.PathLike)):
        with open(tdbinlog_file, 'rb') as file:
            buffer = file.read()
    else:
        buffer = tdbinlog_file.read()

    binlog = Binlog(buffer, password)
    while True:
        try:
            event = binlog.read_next_event()
        except BufferError:  # occurs when no more bytes left to read
            break
        event.validate()

        binlog.process_event(event)

    return binlog
