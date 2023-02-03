#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

#
# This file is supposed to serve as an API for AoT db access
#

import logging
import os
from collections import OrderedDict

# An abstract class for DB frontend


class AotDbFrontend:

    def __init__(self):
        pass

    def create(self, json_file, product, version,
               build_type, drop_on_import, cache_size):
        self.json_file = json_file
        self.product = product.replace(".", "_")
        self.version = version.replace(".", "_")
        self.build_type = build_type
        self.drop_on_import = drop_on_import

        self.db_name = ''
        self.client = None
        self.db = None

        self.query_cache = OrderedDict()
        self.query_cache_size = cache_size

        self.json_data = None

    def __getitem__(self, key):
        return self.collections[key]

    def sanity_check(self):
        if self.json_file and not os.path.isfile(self.json_file):
            logging.error("JSON file {} not found".format(self.json_file))
            return False

        if not self.product:
            logging.error("Product string must be provided")
            return False

        if not self.version:
            logging.error("Version string must be provided")
            return False

        return True

    # The function implements import to db from a db.json file.
    # If import needs to be customized, the user can pass custom function in the constructor.
    # @json_file - the JSON file to import

    def import_db_json(self, json_file):
        pass

    def create_local_index(self, collection_name, field_name, extra_field_name=None,
                           cache_size=0, unique=True):
        return AotDbCollectionQuery(self.db[collection_name], field_name, extra_field_name,
                                    cache_size=cache_size, field_is_unique=unique)

    # This method makes it possible to recursively retrieve objects from the database
    # based on some criterion. For example, starting from a function we can retrieve
    # all functions called by the function and all called by those functions, etc..
    # We need to specify the collection we are interested in, as well as the
    # value we want to match (in case of functions, we match the numbers from "calls" with
    # function ids).

    def _query(self, visited, collection_name, base,
               match_from_field, match_to_field, value_to_return=None, cutoff_list=None):
        return None

    def make_recursive_query(self, collection_name, obj_selector_field, obj_selector_value,
                             match_from_field, match_to_field, value_to_return=None, add_vals=None,
                             cutoff_list=None):
        return None

    def connect(self, direct=False):
        return True

    def disconnect(self):
        pass

    def create_index(self, collection_name, field_name):
        return True

    def store_in_collection(self, name, data):
        pass

    def store_many_in_collection(self, name, data):
        pass

    # makes it possible to add backend-specific arguments for the parser
    def parse_args(self, parser):
        # We can either connect to a DB or populate DB with data imported from JSON
        parser.add_argument('--import-json',
                            default=None,
                            help='The path to a JSON file to be imported')
        parser.add_argument('--drop-on-import',
                            default=False,
                            help='If a DB of the same name as imported exists, drop it')

    def establish_db_connection(self, args):
        return None

    def close_db_connection(self):
        pass

# This class represents a single "table" in the DB. That corresponds to a top-level
# entry of the JSON file, e.g. funcs, sources, etc.


class AotDbCollection():
    name = None

    def __init__(self, name, db, lookup_field):
        self.name = name
        self.db = db
        self.lookup_field = lookup_field

    def __getitem__(self, key):
        return None

    def __contains__(self, key):
        return False

    def __len__(self):
        return 0

    def __iter__(self):
        return None

    def get_range(self, start, stop, order=1):
        return []

    def graphLookup(self, match, lookup, project=None, additional_values=None, append_to_field=None):
        return None

    def find(self, match_to_field, value):
        results = []
        if self.name in self.db:
            for item in self.db[self.name]:
                if item[match_to_field] == value:
                    results.append(item)
        return results

    def find_one(self, match_to_field, value):
        if self.name in self.db:
            for item in self.db[self.name]:
                if item[match_to_field] == value:
                    return item
        return None

# This class makes it possible to dynamically create DB queries to for a given
# CollectionItem object. For example, if we wish to fetch function based on it's id
# we create
# self.fnidmap = CollectionQuery(self.db["funcs"], "id")
# If we then type self.fnidmap[10] that will fetch a JSON object associated with a
# function of id == 10 from the database.


class AotDbCollectionQuery:

    def __init__(self, collection, field, extra_field=None, cache_size=0, field_is_unique=True):
        self.collection = collection
        self.field = field
        self.extra_field = extra_field
        self.cache_size = cache_size
        self.field_is_unique = field_is_unique
        self.cache = OrderedDict()
        self.contains_cache = OrderedDict()

    def __getitem__(self, key):
        return None

    def __contains__(self, key):
        return False

    def get_many(self, list):
        return []

    def get_all(self):
        return []

    def get_count(self, key):
        return 0
