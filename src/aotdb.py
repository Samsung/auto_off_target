#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

#
#   AoT database connection front-end
#

from enum import Enum
import logging

# backends import
from dbjson2ftdb import FtdbFrontend


class DbType(str, Enum):
    FTDB = "ftdb"
    INVALID = "unsupported"


def connection_factory(db_type):
    if db_type == DbType.FTDB:
        return FtdbFrontend()
    else:
        logging.error(f"Invalid backend type {db_type}")
