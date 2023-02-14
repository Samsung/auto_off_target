#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

#
# This module is responsible for higher-level DB operations
# such as: creating a new db for AoT, creating indices
# It encapsulates the logic behind these DB operations and uses the DB
# module for the raw DB access.
#

import logging
import json
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import depth_first_order
import numpy as np
import os
import random


class AotDbOps:

    DATA = 'data'
    ROW_IND = 'row_ind'
    COL_IND = 'col_ind'
    MATRIX_SIZE = 'matrix_size'
    FUNCS_REFS = 'funcs_tree_func_refs'
    FUNCS_REFS_NO_KNOWN = 'funcs_tree_funrefs_no_known'
    FUNCS_REFS_NO_ASM = 'funcs_tree_funrefs_no_asm'
    FUNCS_REFS_NO_KNOWN_NO_ASM = 'funcs_tree_funrefs_no_known_no_asm'
    FUNCS_CALLS = 'funcs_tree_func_calls'
    FUNCS_CALLS_NO_KNOWN = 'funcs_tree_calls_no_known'
    FUNCS_CALLS_NO_ASM = 'funcs_tree_calls_no_asm'
    FUNCS_CALLS_NO_KNOWN_NO_ASM = 'funcs_tree_calls_no_known_no_asm'
    TYPES_REFS = 'types_tree_refs'
    TYPES_USEDREFS = 'types_tree_usedrefs'
    GLOBS_GLOBALREFS = 'globs_tree_globalrefs'

    # #db: AotDBFrontend instance
    def __init__(self, db, basconnector, deps, args):
        self.deps = deps
        self.version = f"{args.product}_{args.version}_{args.build_type}"
        self.include_asm = args.include_asm
        self.fptr_analysis = args.fptr_analysis
        self.db_type = args.db_type

        # global state available to external classes
        self.db = db
        self.bassconnector = basconnector

        # the first group are a special idices to db -> they are fixed on a particular
        # member of a given type, e.g. we can instantly get by id or by name
        # the purpose here is to easily fetch data through a dictionary-like operation, e.g.:
        # self.fnidmap[10] -> fetch a function object for a function of id==10
        self.fnmap = None        # get function by name
        self.fnidmap = None      # get function by id
        self.fdmap = None        # get funcdecl by id
        self.fdnmap = None       # get funcdecl by name
        self.umap = None         # get unresolved func by id
        self.unmap = None        # get unresolved func by name
        self.typemap = None      # get type by id
        self.globalsidmap = None  # get global by id
        self.srcidmap = None     # get source file by id
        self.scrnmap = None      # get source file by name

        # the second group are various sets/lists
        self.init_data = {}              # get user-provided init data by name
        self.lib_funcs = []              # aot library func names
        self.lib_funcs_ids = set()       # aot library func ids
        self.known_funcs_ids = set()     # ids of known funcs
        self.always_inc_funcs_ids = set()  # ids of always included funcs
        self.all_funcs_with_asm = set()  # ids of funcs that include assembly
        self.static_funcs_map = {}       # get list of file ids by static func id
        self.builtin_funcs_ids = set()   # get a list of ids of builtin funcs
        self.fpointer_map = {}           # get function pointers info

        # the third group are precomputed sets which represent entire
        # recursive subtrees for certain features
        # for a given func get its callgraph (set of func ids);
        self.funcs_tree_funrefs = None
        # include all func references in addition to direct calls
        # as above, but exclude known funcs from the computation
        self.funcs_tree_funrefs_no_known = None
        # as above, but exclude funcs with asm from the computation
        self.funcs_tree_funrefs_no_asm = None
        # as above, but exclude known funcs and funcs with asm from the computation
        self.funcs_tree_funrefs_no_known_no_asm = None
        # for a given func get its callgraph (function calls only)
        self.funcs_tree_calls = None
        self.funcs_tree_calls_no_known = None           # same meaning as above
        self.funcs_tree_calls_no_asm = None             # same meaning as above
        self.funcs_tree_calls_no_known_no_asm = None    # same meaning as above
        # for a given type get all types (ids) it depends on
        self.types_tree_refs = None
        # as above, but include only the members/types that are used in the code
        self.types_tree_usedrefs = None
        # for a given global get all globals (ids) it depends on
        self.globs_tree_globalrefs = None

    def __getitem__(self, key):
        return self.db[key]

    def import_aot_db(self, import_json, lib_funcs_file, always_inc_funcs_file,
                      known_funcs_file, init_file, rdm_file):

        json_data = self.db.import_db_json(import_json)

        # create db indices required in this function
        # get function by name
        self.fnmap = self.db.create_local_index("funcs", "name", extra_field_name=None,
                                                cache_size=100000, unique=False)

        # get func decl by name
        self.fdnmap = self.db.create_local_index("funcdecls", "name", extra_field_name=None,
                                                 cache_size=100000, unique=False)

        # get unresolved func name by name
        self.unmap = self.db.create_local_index("unresolvedfuncs", "name", extra_field_name=None,
                                                cache_size=100000, unique=False)

        # create db indices
        collections = ["funcs", "types", "globals",
                       "sources", "funcdecls", "unresolvedfuncs"]
        fields = ["id", "name", "fid", "refs", "usedrefs", "decls", "class", "types", "calls", "funrefs", "fids", "globalrefs",
                  "linkage", "body", "funcdecls", "hash", "implicit", "location", "declbody", "inline", "str", "type", "size",
                  "hasinit", "derefs", "union", "def", "unpreprocessed_body", "refnames", "bitfields", "locals", "signature"]
        for c in collections:
            for f in fields:
                self.db.create_index(c, f)

        if lib_funcs_file is not None:

            _fids, _funcs = self._get_funcs_from_a_text_file(lib_funcs_file)
            self.lib_funcs_ids |= _fids
            self.known_funcs_ids |= _fids
            for name in _funcs:
                self.lib_funcs.append(name)

        else:
            logging.info("No lib functions specified")

        known_data = None

        if always_inc_funcs_file:  # is None:
            #    logging.info("No always include functions file specified: getting data from the db")
            # else:
            logging.info(
                "Will load always include functions from a file")
            _fids, _funcs = self._get_funcs_from_a_text_file(
                always_inc_funcs_file)
            self.always_inc_funcs_ids |= _fids
            logging.info(
                f"Intially we have {len(self.always_inc_funcs_ids)} functions to include")

        if known_funcs_file:  # if self.known_funcs_file is not None:
            load = True

            logging.info(
                "Will discover known functions and types based on a list of function names")

            _fids, _funcs = self._get_funcs_from_a_text_file(known_funcs_file)
            self.known_funcs_ids |= _fids

            # get builtin func ids, funcs with asm and a map of static funcs
            logging.info("Getting builtin functions")
            prefix = "__builtin"

            # if json_data is not None:
            #     funcs = json_data['funcs']
            #     logging.info("using data from local json file")
            # else:
            funcs = self.db["funcs"]

            for f in funcs:
                n = f["name"]
                f_id = f["id"]
                if n.startswith(prefix):
                    self.builtin_funcs_ids.add(f_id)
                # get all functions with asm
                if not self.include_asm:
                    if self._func_contains_assembly(f):
                        self.all_funcs_with_asm.add(f_id)
                self.static_funcs_map[f_id] = []

                if f["linkage"] == "internal":
                    for id in f["fids"]:
                        if id not in self.static_funcs_map[f_id]:
                            self.static_funcs_map[f_id].append(id)

            funcdecls = self.db["funcdecls"]
            for f in funcdecls:
                n = f["name"]
                if n.startswith(prefix):
                    self.builtin_funcs_ids.add(f["id"])

            unresolved = self.db['unresolvedfuncs']
            for f in unresolved:
                n = f["name"]
                if n.startswith(prefix):
                    self.builtin_funcs_ids.add(f["id"])

            tmp_static_funcs_map = []
            for f_id in self.static_funcs_map:
                item = {"id": f_id, "fids": self.static_funcs_map[f_id]}
                tmp_static_funcs_map.append(item)
            self.db.store_many_in_collection(
                "static_funcs_map", tmp_static_funcs_map)

            known_data = {
                "version": self.version,
                "func_ids": list(self.known_funcs_ids),
                "builtin_ids": list(self.builtin_funcs_ids),
                "asm_ids": list(self.all_funcs_with_asm),
                "lib_funcs": list(self.lib_funcs),
                "lib_funcs_ids": list(self.lib_funcs_ids),
                "always_inc_funcs_ids": list(self.always_inc_funcs_ids)
            }

            logging.info("Storing known data in the db")
            # TODO: we only store that data in the db really during the first import
            # currently it's stored whenever the user provides a test file
            self.db.store_in_collection("known_data", known_data)

        # we create recursive hierarchies data off-line and from JSON file
        # during import to DB (since only at that point we have the file available)
        logging.info("Going to create recursive dependencies cache")

        # json_data is initialized above
        funcs = self.db["funcs"]
        types = self.db["types"]
        globs = self.db["globals"]

        # make all recursive queries we might ever need
        logging.info("Performing recursive queries for all funcs")
        known_asm = set()
        known_asm |= set(self.known_funcs_ids)
        known_asm |= set(self.all_funcs_with_asm)

        funcs_size = len(
            funcs) + len(json_data['funcdecls']) + len(json_data['unresolvedfuncs'])
        self.funcs_tree_funrefs = self._create_recursive_cache(
            funcs, funcs_size, "id", "funrefs", AotDbOps.FUNCS_REFS, set())
        self.funcs_tree_funrefs_no_known = self._create_recursive_cache(
            funcs, funcs_size, "id", "funrefs", AotDbOps.FUNCS_REFS_NO_KNOWN, set(self.known_funcs_ids))
        self.funcs_tree_funrefs_no_asm = self._create_recursive_cache(
            funcs, funcs_size, "id", "funrefs", AotDbOps.FUNCS_REFS_NO_ASM, set(self.all_funcs_with_asm))
        self.funcs_tree_funrefs_no_known_no_asm = self._create_recursive_cache(
            funcs, funcs_size, "id", "funrefs", AotDbOps.FUNCS_REFS_NO_KNOWN_NO_ASM, known_asm)
        self.funcs_tree_calls = self._create_recursive_cache(
            funcs, funcs_size, "id", "calls", AotDbOps.FUNCS_CALLS, set())
        self.funcs_tree_calls_no_known = self._create_recursive_cache(
            funcs, funcs_size, "id", "calls", AotDbOps.FUNCS_CALLS_NO_KNOWN, set(self.known_funcs_ids))
        self.funcs_tree_calls_no_asm = self._create_recursive_cache(
            funcs, funcs_size, "id", "calls", AotDbOps.FUNCS_CALLS_NO_ASM, set(self.all_funcs_with_asm))
        self.funcs_tree_calls_no_known_no_asm = self._create_recursive_cache(
            funcs, funcs_size, "id", "calls", AotDbOps.FUNCS_CALLS_NO_KNOWN_NO_ASM, known_asm)

        self.types_tree_refs = self._create_recursive_cache(
            types, len(types), "id", "refs", AotDbOps.TYPES_REFS, set())
        self.types_tree_usedrefs = self._create_recursive_cache(
            types, len(types), "id", "usedrefs", AotDbOps.TYPES_USEDREFS, set())
        self.globs_tree_globalrefs = self._create_recursive_cache(
            globs, len(globs), "id", "globalrefs", AotDbOps.GLOBS_GLOBALREFS, set())

        if self.fptr_analysis:
            # preprocess list of all possible functions assigned to function pointers
            logging.info("Pre-procesing function pointers information")
            fpointers = self.deps._infer_functions(json_data)
            fpointers_for_db = [{"_id": k, "entries": v}
                                   for k, v in fpointers.items()]

            self.db.store_many_in_collection("func_fptrs", fpointers_for_db)
            del fpointers_for_db
            del fpointers

        del funcs
        del types
        del globs
        del json_data

        logging.info("Storing completed")

        # import all data init constraints
        if init_file:
            logging.info("Loading data init file")
            # the user specified a JSON file with data init constraints
            with open(init_file, "r") as f:
                init_data = json.load(f)
                # the file has the following format:
                # [
                #     {
                #       "name": <func/type/global name>,
                #       "items": [
                #       {
                #         "name": <item name>,
                #         "size": <item size - for pointers that's the array size>
                #         "nullterminated": ["True"|"False"]
                #       }
                #       ...
                #       ]
                #     },
                #     ...
                # ]

                self.init_data = {}
                for item in init_data:
                    name = item["name"]
                    self.init_data[name] = item
                logging.info(
                    f"User-provided init data loaded with {len(self.init_data)} entries")

                # store that data in the db
                data = [self.init_data[x] for x in self.init_data]
                self.db.store_many_in_collection("init_data", data)

        if rdm_file is not None:
            self.bassconnector.import_data_to_db(rdm_file)

    def create_indices(self):
        # self.funcs_tree_funrefs = None
        # self.funcs_tree_funrefs_no_known = None
        # self.funcs_tree_funrefs_no_asm = None
        # self.funcs_tree_funrefs_no_known_no_asm = None
        # self.funcs_tree_calls = None
        # self.funcs_tree_calls_no_known = None
        # self.funcs_tree_calls_no_asm = None
        # self.funcs_tree_calls_no_known_no_asm = None

        # self.types_tree_refs = None
        # self.types_tree_usedrefs = None
        # self.globs_tree_globalrefs = None

        # self.known_funcs_ids = set()

        # create db indices as in ctypelib
        # get function by name
        self.fnmap = self.db.create_local_index("funcs", "name", extra_field_name=None,
                                                cache_size=100000, unique=False)
        # get function by id
        self.fnidmap = self.db.create_local_index("funcs", "id", extra_field_name=None,
                                                  cache_size=100000)
        # get func decl by id
        self.fdmap = self.db.create_local_index("funcdecls", "id", extra_field_name=None,
                                                cache_size=100000)

        # get func decl by name
        self.fdnmap = self.db.create_local_index("funcdecls", "name", extra_field_name=None,
                                                 cache_size=100000, unique=False)

        # get unresolved func name by id
        self.umap = self.db.create_local_index("unresolvedfuncs", "id", extra_field_name=None,
                                               cache_size=100000)

        # get unresolved func name by name
        self.unmap = self.db.create_local_index("unresolvedfuncs", "name", extra_field_name=None,
                                                cache_size=100000, unique=False)

        # get type by id
        self.typemap = self.db.create_local_index("types", "id", extra_field_name=None,
                                                  cache_size=100000)
        # get global by id
        self.globalsidmap = self.db.create_local_index("globals", "id", extra_field_name=None,
                                                       cache_size=100000)
        # get source name by id
        self.srcidmap = self.db.create_local_index(
            "sources", "id", "name", cache_size=100000)
        # get source id by name
        self.srcnmap = self.db.create_local_index("sources", "name", "id", cache_size=100000,
                                                  unique=False)

        # try to get what we can from the db
        known_data = self.db.create_local_index("known_data", "version")
        known_data = known_data[self.version]

        if known_data is None:
            logging.warning(
                "The version stored in the db is not the current version - will not use known data")
        else:
            self.builtin_funcs_ids = set()
            self.all_funcs_with_asm = set()
            self.static_funcs_map = {}

            static_funcs = self.db.create_local_index(
                "static_funcs_map", "id").get_all()
            for f in static_funcs:
                f_id = f["id"]
                if "fids" not in f:
                    logging.info(f"'fids' not found in function {f['id']}")
                    continue
                fids = f["fids"]
                self.static_funcs_map[f_id] = set(fids)

            for f_id in known_data['func_ids']:
                self.known_funcs_ids.add(f_id)
            for f_id in known_data['builtin_ids']:
                self.builtin_funcs_ids.add(f_id)
            for f_id in known_data['asm_ids']:
                self.all_funcs_with_asm.add(f_id)

            self.lib_funcs = known_data['lib_funcs']
            self.lib_funcs_ids = known_data['lib_funcs_ids']
            self.always_inc_funcs_ids = set(known_data['always_inc_funcs_ids'])
        logging.info(f"Version is {self.version}")

        # load recursive caches from the database
        logging.info("Create indices for recursive query caches")

        # recursive queries are handled by csr_matix objects
        # we have the necessary data for those objects stored in the db
        funcs = []
        known_asm = set()
        funcs_size = 0
        # if known_functions_updated:
        # known_asm |= set(self.known_funcs_ids)
        # known_asm |= set(self.all_funcs_with_asm)
        # for f in self.db["funcs"]:
        #     funcs.append(f)
        # a, b = self.funcs_tree_funrefs.shape
        # funcs_size = a

        self.types_tree_refs = self._create_cache_matrix(
            self.db, AotDbOps.TYPES_REFS)
        self.types_tree_usedrefs = self._create_cache_matrix(
            self.db, AotDbOps.TYPES_USEDREFS)
        self.globs_tree_globalrefs = self._create_cache_matrix(
            self.db, AotDbOps.GLOBS_GLOBALREFS)

        # self._get_called_functions(self.always_inc_funcs_ids)
        # logging.info(f"Recursively we have {len(self.always_inc_funcs_ids)} functions to include")

        if self.fptr_analysis:
            if self.db_type == 'ftdb':
                # if we're using db.img
                logging.info("Generating function pointers information")
                fpointers = self.deps._infer_functions(self.db.db)
                self.fpointer_map = {k: {"_id": k, "entries": v}
                                     for k, v in fpointers.items()}
            else:
                logging.error(
                    f"Option --fptr-analysis requires db.json imported with function pointers analysis enabled")
                exit(1)

        self.init_data = self.db.create_local_index("init_data", "name")
        self.bassconnector.db_index = self.db.create_local_index(
            "BAS", "loc", extra_field_name=None, cache_size=100000)

    # -------------------------------------------------------------------------

    def get_cache_matrix(self, name):
        if not hasattr(self, name) or getattr(self, name) is None:
            result = self._create_cache_matrix(self.db, name)
            setattr(self, name, result)
        return getattr(self, name)

    # -------------------------------------------------------------------------

    def _create_cache_matrix(self, db, collection_name):
        logging.info(
            f"Generating cache matrix for collection {collection_name}")
        index = self.db.create_local_index(collection_name, "name")
        data = index[AotDbOps.DATA]
        row_ind = index[AotDbOps.ROW_IND]
        col_ind = index[AotDbOps.COL_IND]
        np_data = np.array(data["data"])
        np_row_ind = np.array(row_ind["data"])
        np_col_ind = np.array(col_ind["data"])
        size = index[AotDbOps.MATRIX_SIZE]['data']

        matrix = csr_matrix(
            (np_data, (np_row_ind, np_col_ind)), shape=(size, size))

        return matrix

    # -------------------------------------------------------------------------

    def _create_recursive_cache(self, _items, size, match_from, match_to, collection_name, cutoff=set()):

        logging.info(f"Graph size is {size}")

        data = []
        row_ind = []
        col_ind = []
        ids = []
        for item in _items:
            item_id = item[match_from]
            if cutoff and item_id in cutoff:
                continue
            ids.append(item_id)
            if match_to not in item:
                continue
            match_list = item[match_to]
            for _id in match_list:
                if cutoff and _id in cutoff:
                    continue
                if _id < 0:
                    continue
                row_ind.append(item_id)
                col_ind.append(_id)
                if _id == item_id:
                    # self cycles counted as 2
                    data.append(2)
                else:
                    data.append(1)
        np_data = np.array(data)
        np_row_ind = np.array(row_ind)
        np_col_ind = np.array(col_ind)
        matrix = csr_matrix(
            (np_data, (np_row_ind, np_col_ind)), shape=(size, size))
        logging.info("Matrix created")
        # need to break the matrix data into 3 due to the mongo limit of a single document size
        self.db.store_in_collection(
            collection_name, {"name": AotDbOps.DATA, "data": data})
        self.db.store_in_collection(
            collection_name, {"name": AotDbOps.ROW_IND, "data": row_ind})
        self.db.store_in_collection(
            collection_name, {"name": AotDbOps.COL_IND, "data": col_ind})
        self.db.store_in_collection(
            collection_name, {"name": AotDbOps.MATRIX_SIZE, "data": size})

        return matrix

    # -------------------------------------------------------------------------

    @staticmethod
    def _graph_dfs(csr_matrix, item):
        nodes = depth_first_order(
            csr_matrix, item, directed=True, return_predecessors=False)
        nodes_int = [n.item() for n in nodes]
        return nodes_int[1:]

    # -------------------------------------------------------------------------

    # given a text file with function names (one name per line)
    # return a list of ids
    def _get_funcs_from_a_text_file(self, filename):
        _fids = set()
        _funcs = set()
        with open(filename, "r") as f:
            lines = f.readlines()
            for l in lines:
                func = l.replace("\n", "")
                logging.info(func)
                fids = set()
                if self.fnmap[func] is not None:
                    fid = self.fnmap[func]
                elif self.fdnmap[func] is not None:
                    fid = self.fdnmap[func]
                elif self.unmap[func] is not None:
                    fid = self.unmap[func]
                else:
                    logging.error(
                        f"Function {func} from known funcs file not found")
                    continue
                if isinstance(fid, list):
                    for item in fid:
                        fids.add(int(item["id"]))
                else:
                    fids.add(int(fid["id"]))

                if len(fids) == 0:
                    continue
                elif len(fids) > 1:
                    logging.error(
                        f"Function {func} from library maps to more than one id")
                _fids |= fids
                _funcs.add(func)

        return _fids, _funcs

    # -------------------------------------------------------------------------

    def _func_contains_assembly(self, f):
        if "asm" not in f:
            return False
        if len(f["asm"]) == 0:
            return False
        return True

    # -------------------------------------------------------------------------

    def _find_potential_targets(self):
        logging.info("going to find interesting test targets")
        uncalled_funcs = set()
        for f in self.db['funcs']:
            uncalled_funcs.add(f['id'])

        logging.info(f"there are a total of {len(uncalled_funcs)} functions")
        for f in self.db['funcs']:
            for ref in f["calls"]:
                if ref in uncalled_funcs:
                    uncalled_funcs.remove(ref)
        logging.info(
            f"There are {len(uncalled_funcs)} functions that noone calls")
        locations = {}
        zerocalls = 0

        copy = set(uncalled_funcs)
        for f_id in copy:

            f = self.fnidmap[f_id]
            if len(f['calls']) == 0 and f_id in uncalled_funcs:
                uncalled_funcs.remove(f_id)
            if f_id in self.all_funcs_with_asm and f_id in uncalled_funcs:
                uncalled_funcs.remove(f_id)
        logging.info(f"we are left with {len(uncalled_funcs)} functions")

        counter = 0
        interesting = set()
        for f_id in uncalled_funcs:

            funcs = set([f_id])

            self.deps.known_funcs_present = set()
            self.deps._get_called_functions(funcs, None, True, True, True)
            # let's check if there are functions of interest in the subtrees of our functions
            found = False
            for name in self.deps.known_funcs_present:
                if name == 'copy_from_user' or name == "copy_to_user":
                    counter += 1
                    found = True
                    interesting.add(f_id)
                    break

            if not found:
                for _id in funcs:
                    f = self.fnidmap[_id]
                    if f is not None:
                        if f['name'] == 'copy_from_user' or "__replacement____get_user__" in f['body'] or f['name'] == 'copy_to_user' or "__replacement____put_user__" in f['body']:
                            if f['name'] == "__dump_instr":
                                continue
                            counter += 1
                            interesting.add(f_id)
                            break

        for f_id in interesting:
            f = self.fnidmap[f_id]
            logging.info(f"AOT_TARGET: {f['name']}: {f['declbody']}: {f['id']}")

        logging.info(
            f"We have {counter} functions that call interesting functions in their subtrees")

        # for f_id in uncalled_funcs:
        #     f = self.dbops.fnidmap[f_id]
        #     l = os.path.dirname(f['location'])
        #     if l not in locations:
        #         locations[l] = 0
        #     locations[l] += 1

        # for l in locations:
        #     logging.info(f"{l} : {locations[l]}")

    # -------------------------------------------------------------------------

    def _find_random_targets(self, number):
        total = len(self.db["funcs"])
        logging.info(f"There is a total of {total} functions in the database")

        all_ids = []
        for f in self.db["funcs"]:
            all_ids.append(f['id'])

        selected = random.sample(all_ids, number)

        logging.info(
            f"We have selected the following {len(selected)} functions:")
        for f_id in selected:
            f = self.fnidmap[f_id]
            if f is None:
                logging.error(f"unable to find a function for id {f_id}")
            name = f['name']
            file = os.path.basename(f['location'])
            index = file.find(":")
            if -1 != index:
                file = file[:index]
            logging.info(f"AOT_RANDOM_FUNC: {f_id}")

    # -------------------------------------------------------------------------

    def _get_unique_names(self, namesfile):
        fids, funcs = self._get_funcs_from_a_text_file(namesfile)
        fails = 0
        for f_id in fids:
            f = self.fnidmap[f_id]
            if f:
                name = f['name']
                file = f['location']

                index = file.find(":")
                if -1 != index:
                    file = file[:index]
                logging.info(f"AOT_UNIQUE_NAME: {name}@{file}")
            else:
                fails += 1
        logging.info(f"Finished generating unique names, fail count {fails}")

    # -------------------------------------------------------------------------

    def _get_function_file(self, function_id):
        if function_id not in self.fnidmap:
            if function_id not in self.fdmap:
                logging.error("Function {} not found".format(function_id))
                return None, None, None
            else:
                function = self.fdmap[function_id]
        else:
            function = self.fnidmap[function_id]
        fid = function["fid"]
        src = self.srcidmap[fid]
        srcs = []
        if "fids" in function:
            fids = function["fids"]
            for entry in self.srcidmap.get_many([fid for fid in fids]):
                srcs.append(entry)
        else:
            # if fids not present for some reason, we still have fid
            srcs.append(src)

        loc = function["location"]

        end_index = loc.find(":")
        if -1 != end_index:
            loc = loc[:end_index]

        return src, loc, srcs

    # -------------------------------------------------------------------------

    def _get_function_name(self, function_id):
        if function_id in self.fnidmap:
            return self.fnidmap[function_id]["name"]
        elif function_id in self.fdmap:
            return self.fdmap[function_id]["name"]
        elif function_id in self.umap:
            return self.umap[function_id]["name"]
        else:
            logging.error(
                f"Function id {function_id} not found in the database")
            return None

    # -------------------------------------------------------------------------

    # A generic function for recursive retrieval of data
    # @collection - collection name
    # @items - list o items to begin with
    # @match_from_field - name of the field to match
    # @skip_list - items to skip in the results
    # @belongs: dbops
    def _get_recursive_by_id(self, collection, items, match_from_field, skip_list=None):
        all_items = set()

        for i in items:

            if self.globs_tree_globalrefs is not None and collection == "globals" and match_from_field == "globalrefs":
                # = self.dbops.globs_tree_globalrefs[i][match_from_field]
                result_ids = self._graph_dfs(self.globs_tree_globalrefs, i)
            elif self.types_tree_refs is not None and collection == "types" and match_from_field == "refs":
                # = self.dbops.types_tree_refs[i][match_from_field]
                result_ids = self._graph_dfs(self.types_tree_refs, i)
            elif self.types_tree_usedrefs is not None and collection == "types" and match_from_field == "usedrefs":
                # = self.dbops.types_tree_usedrefs[i][match_from_field]
                result_ids = self._graph_dfs(self.types_tree_usedrefs, i)
            else:
                result_ids = self.db.make_recursive_query(
                    collection,
                    "id",
                    i,
                    match_from_field,
                    "id",
                    "id")

            if i not in result_ids:
                result_ids.append(i)

            for id in result_ids:
                if skip_list is not None:
                    if id not in skip_list:
                        all_items.add(id)
                    else:
                        logging.debug("Skipping id {}".format(id))
                else:
                    all_items.add(id)

        return all_items

    # -------------------------------------------------------------------------

    # Give a type id, return a destination type. It will be tid, except for
    # const_array, incomplete_array and pointer, for which a destination type
    # is returned
    # @belongs: init
    def _get_real_type(self, t_id):
        t = self.typemap[t_id]
        cl = t["class"]
        if cl == "const_array" or cl == "incomplete_array" or cl == "pointer":
            # for these classes we need to get the destination type as the types
            # themselves are just a proxy
            dst_tid = t["refs"][0]
            dst_tid = self._get_real_type(dst_tid)
        else:
            dst_tid = t_id

        return dst_tid

    # -------------------------------------------------------------------------

    # A utility function used to get the destination type of a typedef.
    # If the provided type is not typedef, its id is returned straight away.
    # @belongs: init? some of the funcs are kind of generic, could be codegen as well
    def _get_typedef_dst(self, t):
        cl = t["class"]
        tmp_t = t
        while (cl == "typedef"):
            t_id = tmp_t["refs"][0]
            tmp_t = self.typemap[t_id]
            cl = tmp_t["class"]
        return tmp_t

    # -------------------------------------------------------------------------

    # A helper function. It is supposed to help detect the types which are defined
    # along with the global.
    # For a given set of decls and refs and global type return a set of types
    # defined with the global as well as the global's true type (in case the type is
    # an array or a pointer)
    # @belongs: ?
    def _get_global_decl_types(self, decls, refs, type):
        ret_tids = set()
        for d in decls:
            t_id = refs[d]
            ret_tids.add(self._get_real_type(t_id))

        # now, let's get the true type of the global
        real_tid = self._get_real_type(type)
        return ret_tids, real_tid
