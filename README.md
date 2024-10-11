# td.binlog-reader
 Any [TDLib](https://github.com/tdlib/td) application stores its cache data inside the **td.binlog** file. All data is stored as a **dictionary**, with keys and values. It contains: datacenters' info, auth keys, locales etc. This utility will help you to decode **td.binlog** file and use its map.

## Setup

Install the tgcrypto cryptographic library to use aes256 encryption function
```
$ pip install tgcrypto
```

## Usage

1. Run main.py file using python to test a script.
2. Modify program logic the way it fits your needs (extracting values of different keys, parsing them, etc.).
