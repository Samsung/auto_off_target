#!/usr/bin/evn python3

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import os
import sys
import json
import logging
import hashlib
from aotdb_api import AotDbCollection
from aotdb_api import AotDbCollectionQuery
from aotdb_api import AotDbFrontend
from collections import OrderedDict
import ftdb_indices

try:
    import libftdb
except ImportError as e:
    print(f"Unable to import libftdb: {e}")


class FtdbFrontend(AotDbFrontend):

    def __init__(self):
        pass

    def create(self, json_file, product, version,
               build_type, drop_on_import, db_file, cache_size):
        super().create(json_file, product, version,
                       build_type, drop_on_import, cache_size)
        self.db_file = db_file

    def sanity_check(self):
        if not super().sanity_check():
            return False

        if self.db_file and not os.path.isfile(self.db_file):
            logging.error(f"db file {self.db_file} not found")
            return False

        if self.db_file and self.json_file:
            logging.error(f"Cannot use both --import-json and --db")
            return False

        if self.db_file is None and self.json_file is None:
            logging.error(
                f"Must specify either --json-file (import) or --db (normal use)")
            return False

        return True

    @staticmethod
    def _json_indices(data):
        function_name_index = dict()
        for func in data["funcs"]:
            function_name_index[func["name"]] = func

        funcdecl_name_index = dict()
        for funcdecl in data["funcdecls"]:
            funcdecl_name_index[funcdecl["name"]] = funcdecl

        return {
            "funcs": {
                "name": function_name_index.get,
            },
            "funcdecls": {
                "name": funcdecl_name_index.get,
            }
        }

    def import_db_json(self, json_file):
        with open(json_file, "r") as f:
            logging.info("Loading JSON data from file")
            self.json_data = json.load(f)
            logging.info("Data loaded!")
            # during the import phase we want to use the json data as the db
            # after the import, ftdb will be used
            self.db = self.json_data
            # since we might be addming more to the db, we
            # don't store the data at this moment
        self.indices = self._json_indices(self.db)
        self._init_collections()

        return self.json_data

    def _init_collections(self):
        self.collections = dict()
        for name in self.collection_names:
            self.collections[name] = FtdbCollection(
                name, self.db, "id", self.indices.get(name)
            )

    def create_local_index(self, collection_name, field_name, extra_field_name=None, cache_size=0, unique=True):
        name = collection_name
        if collection_name == "sources":
            name = "source_info"
        elif collection_name == "modules":
            name = "module_info"
        if name not in self.collections:
            raise Exception(f"Collection {name} does not exist")
        return FtdbCollectionQuery(self.collections[name], field_name, extra_field_name,
                                   cache_size=cache_size, field_is_unique=unique)

    def _query(self, visited, collection_name, base, match_from_field, match_to_field, value_to_return=None, cutoff_list=None):
        collection = self.db[collection_name]
        returned = []

        if base[match_to_field] in visited:
            return returned

        visited.add(base[match_to_field])
        results = None
        from_obj = base[match_from_field]

        if isinstance(from_obj, list):
            for item in from_obj:
                if item in visited:
                    continue

                results = self.collections[collection_name].find(
                    match_to_field, item)
                for r in results:
                    if r[match_to_field] in visited:
                        continue
                    if cutoff_list is not None and r[match_to_field] in cutoff_list:
                        visited.add(r[match_to_field])

                        continue

                    returned += self._query(visited, collection_name, r,
                                            match_from_field, match_to_field, value_to_return, cutoff_list)
                    if value_to_return is not None:
                        returned.append(r[value_to_return])
                    else:
                        returned.append(r)
        elif isinstance(from_obj, str):

            results = self.collections[collection_name].find(
                match_to_field, from_obj)
            for r in results:

                if r[match_to_field] in visited:
                    continue
                if cutoff_list is not None and r[match_to_field] in cutoff_list:
                    visited.add(r[match_to_field])
                    continue

                returned += self._query(visited, collection_name, r,
                                        match_from_field, match_to_field, value_to_return, cutoff_list)

                if value_to_return is not None:
                    returned.append(r[value_to_return])
                else:
                    returned.append(r)
        else:
            logging.error("Unsupported field type!")
            return None

        return returned

    def make_recursive_query(self, collection_name, obj_selector_field, obj_selector_value, match_from_field, match_to_field, value_to_return=None, add_vals=None, cutoff_list=None):
        hash_str = f"{collection_name}{obj_selector_field}{obj_selector_value}" +\
                   f"{match_from_field}{match_to_field}{value_to_return}{add_vals}{cutoff_list}"
        hash_str = hashlib.md5(hash_str.encode()).hexdigest()

        if hash_str in self.query_cache:
            logging.debug("This exact query happened before")
            return self.query_cache[hash_str]

        visited = set()
        # get the object from which the search starts

        base = self.collections[collection_name].find_one(
            obj_selector_field, obj_selector_value)

        # check base for null (not found)
        if base is None:
            ret = []
            return ret
        if add_vals:
            # the user specified additional values to query for
            tmp = base[match_from_field]
            if not isinstance(tmp, list):
                logging.error(
                    "Additional values specified but the destination field is not a list")
            else:
                base[match_from_field] += list(add_vals)
                logging.debug("now {} field is {}".format(
                    match_from_field, base[match_from_field]))

        ret = self._query(visited, collection_name, base,
                          match_from_field, match_to_field, value_to_return, cutoff_list)

        if self.query_cache_size > 0:
            self.query_cache[hash_str] = ret
            if len(self.query_cache) > self.query_cache_size:
                self.query_cache.popitem(last=False)
                logging.debug("QUERY CACHE FULL")

        return ret

    def connect(self):
        # The DB name is created based on product, version and build type
        self.db_name = "compilation_db_{}-{}-{}".format(
            self.product, self.version, self.build_type)

        self.db = libftdb.ftdb()

        # # If a JSON file was specified we'll import it into the DB
        # if self.json_file:
        #     with open(self.json_file, "r") as f:
        #         logging.info("Loading JSON data from file")
        #         self.json_data = json.load(f)
        #         logging.info("Data loaded!")
        #         # during the import phase we want to use the json data as the db
        #         # after the import, ftdb will be used
        #         self.db = self.json_data

        self.collection_names = ["BAS", "funcdecls", "funcs", "funcs_tree_calls_no_asm",
                                 "funcs_tree_calls_no_known", "funcs_tree_calls_no_known_no_asm",
                                 "funcs_tree_func_calls", "funcs_tree_func_refs", "funcs_tree_funrefs_no_asm",
                                 "funcs_tree_funrefs_no_known", "funcs_tree_funrefs_no_known_no_asm",
                                 "globals", "globs_tree_globalrefs", "init_data", "known_data", "modules",
                                 "sources", "static_funcs_map", "types", "types_tree_refs", "types_tree_usedrefs",
                                 "unresolvedfuncs", "source_info", "module_info"]
        if self.db_file:
            logging.info(f"Loading data from {self.db_file} file")
            if not self.db.load(self.db_file, quiet=True):
                logging.error(f"Loading data from {self.db_file} failed")
                return False

            self.indices = ftdb_indices.create_indices(self.db)
            self._init_collections()

        return True

    def disconnect(self):
        if self.json_file:
            # it means that we are in the import stage
            # so we have to store the db (which is an in-memory JSON dict) to a ftdb file

            # sort out 'sources' and 'modules'
            new_sources = []
            for item in self.db['sources']:
                for k in item:
                    new_sources.append({'id': item[k], 'name': k})
            self.db['source_info'] = new_sources
            new_modules = []
            if 'modules' in self.db:
                for item in self.db['modules']:
                    for k in item:
                        new_modules.append({'id': item[k], 'name': k})
                self.db['module_info'] = new_modules

            filename = self.json_file.replace(".json", ".img")
            logging.info(f"Storing database to {filename} file")
            libftdb.create_ftdb(self.db, filename, True)
            # with open(filename, "w") as f:
            #    json.dump(self.db, f, indent=4)

    def store_in_collection(self, name, data):
        if name not in self.db:
            self.db[name] = []
        self.db[name].append(data)

    def store_many_in_collection(self, name, data):
        if name not in self.db:
            self.db[name] = []
        for d in data:
            self.db[name].append(d)

    # makes it possible to add backend-specific arguments for the parser
    def parse_args(self, parser):
        super().parse_args(parser)

    def establish_db_connection(self, args):
        # get the JSON file
        self.create(args.import_json,
                    args.product,
                    args.version,
                    args.build_type,
                    args.drop_on_import,
                    args.db,
                    cache_size=100000)

        if not self.sanity_check():
            logging.error("Parameters sanity check failed. Exiting.")
            sys.exit(1)

        if not self.connect():
            logging.error("Connection to DB failed. Exiting")
            sys.exit(1)

        return self

    def close_db_connection(self):
        self.disconnect()


class FtdbCollectionQuery(AotDbCollectionQuery):

    def __init__(self, collection, field, extra_field=None, cache_size=0, field_is_unique=True):
        self.collection = collection
        self.field = field
        self.extra_field = extra_field
        self.cache_size = cache_size
        self.field_is_unique = field_is_unique
        self.cache = OrderedDict()
        self.contains_cache = OrderedDict()

    def __getitem__(self, key):
        item = None
        cache_hit = False
        if self.cache_size > 0:
            if key in self.cache:
                item = self.cache[key]
                cache_hit = True

        if cache_hit == False:
            if self.field_is_unique:
                item = self.collection.find_one(self.field, key)
            else:
                # in this case "item" might be a list as there is a potential 1-many mapping
                tmp = self.collection.find(self.field, key)
                item = []
                for element in tmp:
                    item.append(element)
                if len(item) == 0:
                    item = None

            if self.cache_size > 0:
                self.cache[key] = item
                if len(self.cache) > self.cache_size:
                    self.cache.popitem(last=False)
                    logging.debug("CACHE FULL")

        if item is not None and self.extra_field is not None:
            if self.field_is_unique:
                item = item[self.extra_field]
            else:
                for i in range(len(item)):
                    item[i] = item[i][self.extra_field]

        if item is not None and not self.field_is_unique and len(item) == 1:
            # no need to create 1-element lists
            item = item[0]
        return item

    def __contains__(self, key):
        if self.cache_size > 0:
            if key in self.contains_cache:
                return self.contains_cache[key]

        item = self.collection.find_one(self.field, key)
        ret = True
        if None is item:
            ret = False

        if self.cache_size > 0:
            self.contains_cache[key] = ret
            if len(self.contains_cache) > self.cache_size:
                self.contains_cache.popitem(last=False)
                logging.debug("CACHE FULL")

        return ret

    def get_many(self, list):
        # we only support unique lists
        if len(list) != len(set(list)):
            return None

        if self.cache_size > 0:
            # if we use cache, try multiple getitem calls (chances are the items are already in the cache)
            result = []
            for item in list:
                data = self.__getitem__(item)
                if data is not None:
                    if self.field_is_unique:
                        result.append(data)
                    else:
                        result = result + data

            return result

        result = []
        for item in list:
            r = self.collection.find_one(self.field, item)
            if r is not None:
                result.append(r)
        return result

    def get_all(self):
        return self.collection

    def get_count(self, key):
        return len(self.collection.find(self.field, key))


class FtdbCollection(AotDbCollection):

    def __init__(self, name, db, lookup_field, indices=None):
        super().__init__(name, db, lookup_field, indices)

    def __getitem__(self, key):
        return super().find_one(self.lookup_field, key)

    def __contains__(self, key):
        item = super().find_one(self.lookup_field, key)
        if None is item:
            return False
        return True

    def __len__(self):
        return len(self.db[self.name])

    def __iter__(self):
        return iter(self.db[self.name])
