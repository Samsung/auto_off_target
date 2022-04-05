#!/usr/bin/env python3

#
#   AoT database connection front-end
#

from enum import Enum
import logging

# backends import
from dbjson2ftdb import FtdbBackend

class DbType(Enum):
    FTDB = 1
    INVALID = 3

def connection_factory(db_type):
    if db_type == DbType.FTDB:
        return FtdbBackend()
    else:
        logging.error(f"Invalid backend type {db_type}")