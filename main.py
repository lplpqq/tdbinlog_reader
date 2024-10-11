import sys

from binlog import read
from binlog.exceptions import InvalidPassword, BinlogEventInvalid
from binlog.models import AuthKey
from binlog.tl_parser import TlParser

tdbinlog_file_path = input('Enter the path to the td.binlog file: ')


def to_int(data: bytes) -> int:
    if data.startswith(b'I'):
        data = data[1:]
    return int(data.decode())


def to_str(data: bytes) -> str:
    if data.startswith(b'S'):
        data = data[1:]
    return data.decode()


def to_bool(data: bytes) -> bool:
    if data.startswith(b'B'):
        data = data[1:]
    return data == b'true'


try:
    binlog = read(tdbinlog_file_path)
except InvalidPassword:
    print('invalid password')
except BinlogEventInvalid:
    print('invalid binlog')
else:
    map_ = binlog.map

    if map_.get('auth') == b'ok':
        try:
            dc_id = to_int(map_['main_dc_id'])
        except KeyError:
            try:
                dc_id = to_int(map_['webfile_dc_id'])
            except KeyError:
                print('failed to locate dc_id')
                sys.exit()

        print(f'{dc_id=}')

        user_id = to_int(map_['my_id'])
        print(f'{user_id=}')

        raw_auth_key: bytes = map_[f'auth{dc_id}']
        auth_key = AuthKey.parse(TlParser(raw_auth_key))
        print(f'{auth_key.auth_key=}')

        # phone_number = to_str(map_['my_phone_number'])
        # print(f'{phone_number=}')
        #
        # was_online_remote = to_int(map_['my_was_online_remote'])
        # print(f'{was_online_remote=}')
        #
        # was_online_local = to_int(map_['my_was_online_local'])
        # print(f'{was_online_local=}')
        #
        # authorization_date = to_int(map_['authorization_date'])
        # print(f'{authorization_date=}')
        #
        # test_mode = to_bool(map_['test_mode'])
        # print(f'{test_mode=}')
        #
        # language_pack = to_str(map_['language_pack_id'])
        # print(f'{language_pack=}')
    else:
        print('user is not authorized')
