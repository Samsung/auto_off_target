#!/usr/bin/env python3

# Auto off-target PoC
###
# Based on sec-tools/misc/fuzzwrap by b.zator@samsung.com
# Developed by    t.kuchta@samsung.com
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import subprocess
import shutil
import json
import logging
import tempfile
import argparse
import sys
import os
from datetime import datetime
import resources
from BASconnector import BASconnector
import aotdb
from aotdb_ops import AotDbOps
from deps import Deps
from init import Init
from codegen import CodeGen
from cutoff import CutOff
from otgenerator import OTGenerator


class File:

    def __init__(self):
        self.funcs = []
        self.globals = []
        self.types = []
        self.filename = ""


class Engine:
    LOGFILE = "aot.log"

    DEFAULT_OUTPUT_DIR = 'off-target'

    GLOBAL_HASH_FILE = 'global.hashes'

    FUNCTION_POINTER_STUB_FILE_TEMPLATE = "fptr_stub.c.template"
    FUNCTION_POINTER_STUB_FILE_SOURCE = "fptr_stub.c"
    FUNCTION_POINTER_KNOWN_FUNCS_STUB_FILE_TEMPLATE = "fptr_stub_known_funcs.c.template"
    FUNCTION_POINTER_KNOWN_FUNCS_STUB_FILE_SOURCE = "fptr_stub_known_funcs.c"

    def __init__(self):
        self.functions = set()
        self.out_dir = Engine.DEFAULT_OUTPUT_DIR

        # to create
        self.sources_to_types = {}
        self.file_contents = {}

    # -------------------------------------------------------------------------

    def init(self, args, db_frontend):
        self.out_dir = args.output_dir

        # create output directory
        # TODO: perhaps it's the job of OTGenerator to prepare the output dir and call the resource manager
        if os.path.exists(self.out_dir):
            msg = f"The output directory {self.out_dir} already exists!"
            logging.error(msg)
            with open(self.out_dir + "/" + "out_dir_error.txt", "w") as file:
                file.write(msg)
            return False

        # create OT output directory
        os.makedirs(self.out_dir)

        # copy the predefined files
        resources_dir = os.path.join(os.path.dirname(__file__), "resources")
        self.resourcemgr = resources.resourcemgr_factory(resources_dir, self.out_dir)
        self.resourcemgr.copy_resources()

        if not self._sanity_check(args):
            logging.error("Sanity check failed in the Engine object")
            return False

        # 1) DB connection
        self.db_frontend = db_frontend
        db_handle = db_frontend.establish_db_connection(args)

        self.libc_includes = args.libc_includes
        self.include_asm = args.include_asm

        self.external_inclusion_margin = args.external_inclusion_margin

        self.cut_off = args.cut_off

        self.use_real_filenames = args.use_real_filenames

        self.smart_init = args.init
        self.dump_smart_init = args.dump_smart_init
        self.dynamic_init = args.dynamic_init

        self.verify_struct_layout = args.verify_struct_layout
        self.dump_ids = args.dump_ids

        self.dump_global_hashes = args.dump_global_hashes
        self.global_hashes = []

        basserver = "localhost"
        bassconnector = None
        if args.config:
            with open(args.config, "r") as c:

                logging.info(f"AOT_CONFIG:|{args.config}|")

                cfg = json.load(c)
                if "BASserver" not in cfg:
                    logging.error("Cannot find BASserver in the config file.")
                    return False

                basserver = cfg["BASserver"]
        if not args.debug_bas:
            bassconnector = BASconnector(basserver, args.product,
                                              args.version, args.build_type, db=db_handle)
        else:
            bassconnector = BASconnector(basserver, db=db_handle)

        self.deps = Deps(args)
        self.dbops = AotDbOps(db_handle, bassconnector, self.deps, args)
        self.cutoff = CutOff(self.dbops, args, bassconnector, self.deps)
        self.codegen = CodeGen(self.dbops, self.deps, self.cutoff, args)
        self.deps.set_dbops(self.dbops)
        self.deps.set_codegen(self.codegen)
        self.deps.set_cutoff(self.cutoff)
        self.init = Init(self.dbops, self.cutoff, self.deps,
                         self.codegen, args)
        self.codegen.set_init(self.init)
        self.otgen = OTGenerator(
            self.dbops, self.deps, self.codegen, self.cutoff, self.init, args)
        self.codegen.set_otgen(self.otgen)
        if args.import_json:
            self.dbops.import_aot_db(args.import_json, args.lib_funcs_file,
                                     args.always_inc_funcs_file, args.known_funcs_file, args.init_file,
                                     args.rdm_file)

        self.dbops.create_indices()
        self.deps._get_called_functions(self.dbops.always_inc_funcs_ids)
        logging.info(
            f"Recursively we have {len(self.dbops.always_inc_funcs_ids)} functions to include")

        self.deps.discover_type_duplicates()
        self.deps.discover_internal_types()

        if args.find_potential_targets:
            # we will look for a potential testing targets
            self.dbops._find_potential_targets()
            return False

        if args.get_unique_names:
            # let's find a non-unique function names
            self.dbops._get_unique_names(args.get_unique_names)
            return False

        if int(args.find_random_targets) != 0:
            self.dbops._find_random_targets(int(args.find_random_targets))
            return False

        if args.debug_analyze_types:
            # analyze all types
            self.init._analyze_types()
            return False

        self.debug_vars_init = args.debug_vars_init

        return True

    # -------------------------------------------------------------------------

    def deinit(self):
        self.db_frontend.close_db_connection()

    # -------------------------------------------------------------------------

    # @depth: if 0, considers only functions from the same directory as
    #         the function of interest, if 1 consider also functions
    #         from 1 dir up, etc.

    def generate_off_target(self, function_names, depth=0):
        # use type and function information
        # to generate off-target source code

        all_funcs_with_asm_copy = self.dbops.all_funcs_with_asm
        self.dbops.all_funcs_with_asm = set()
        self.function_names = function_names

        function_ids = []

        # let's check if the user provided function ids instead of names
        for i in range(len(function_names)):
            if function_names[i].isdigit():
                f_id = int(function_names[i])
                func = self.dbops.fnidmap[f_id]
                f = func['name']
                if not self.include_asm and self.dbops._func_contains_assembly(func):
                    logging.error(
                        f"Cannot generate off-target for {f} as it contains an inline assembly")
                    with open(self.out_dir + "/" + func["name"] + "_error.txt", "w") as file:
                        file.write(
                            "Cannot generate off-target due to inline assembly\n")
                    continue

                function_ids.append(f_id)
                function_names.remove(function_names[i])

        if len(function_names) > 0:
            # first, since we're using function names, we have to ensure that the names
            # uniquely identify a function in the db.json;
            # if a single name is present in multiple files, the user can narrow down
            # the search by using the following notation: function_name@file_name
            tmp = [f.split("@") for f in function_names]
            logging.info(tmp)
            locations = {}
            for f in tmp:
                if len(f) == 2:
                    if f[0] in locations and f[1] in locations[f[0]]:
                        # we already have that function
                        continue
                    if f[0] not in locations:
                        locations[f[0]] = []
                    p = f[1]
                    locations[f[0]].append(p)
                    locations[f[0]].append(f[1])
                else:
                    locations[f[0]] = []

            function_ids = []
            for f, loc in locations.items():
                if f not in self.dbops.fnmap:
                    logging.error("Function {} not found!".format(f))
                    with open(self.out_dir + "/" + f + "_error.txt", "w") as file:
                        file.write(f"Unable to find function {f}\n")
                    return False
                cnt = self.dbops.fnmap.get_count(f)
                if cnt != 1:
                    logging.warning(
                        "Expected 1 occurrence of function {}, found {}.".format(f, cnt))
                    # try to narrow down the search
                    files = locations[f]
                    tmp = self.dbops.fnmap.get_many([f])
                    success = False
                    before = len(function_ids)
                    locs = set()
                    for func in tmp:
                        fid = func["id"]
                        src, loc, srcs = self.dbops._get_function_file(fid)
                        locs.add(loc)
                        # filename = os.path.basename(src)
                        filename = src
                        logging.info(
                            "Searched file {}, function file {}".format(files, filename))
                        subpath = False
                        for path in files:
                            if path in filename:
                                subpath = True
                        if subpath is True or filename in files or os.path.basename(src) in files:
                            if not self.include_asm and self.dbops._func_contains_assembly(func):
                                logging.error(
                                    f"Cannot generate off-target for {f} as it contains an inline assembly")
                                continue
                            function_ids.append(fid)
                            success = True
                            logging.info(
                                "Successfully located function {} (id: {}) in file {}".format(f, fid, loc))
                    after = len(function_ids)
                    if ((after - before) > 1):
                        logging.warning(
                            "We still have more than one function candidate")
                        success = False

                    if success == False:
                        logging.error(("Unable to uniquely locate function {}. " +
                                       "Please try the following notation: function_name@file_name").format(f))
                        logging.error(
                            f"Possible locations for function {f} are: {locs}")
                        with open(self.out_dir + "/" + f + "_error.txt", "w") as file:
                            file.write(
                                f"Unable to uniquely locate function {f}\n")

                        return False
                else:
                    func = self.dbops.fnmap[f]
                    if not self.include_asm and self.dbops._func_contains_assembly(func):
                        logging.error(
                            f"Cannot generate off-target for {f} as it contains an inline assembly")
                        with open(self.out_dir + "/" + func["name"] + "_error.txt", "w") as file:
                            file.write(
                                "Cannot generate off-target due to inline assembly\n")
                        continue
                    function_ids.append(func["id"])

        if 0 == len(function_ids):
            logging.error("No functions to generate")
            # shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")
            # sys.exit(0)
            return False

        # first we need to gather the required data
        # we start with getting all the functions called by our function of interest

        # get the base directories - that is based on the location of the
        # functions of interest
        basedirs = set()
        for f in function_ids:
            self.functions.add(f)
            src, loc, srcs = self.dbops._get_function_file(f)

            dir = os.path.dirname(src)

            for i in range(depth):
                dir = os.path.dirname(dir)
            logging.info("adding basedir {}".format(dir))
            basedirs.add(dir)


        self.deps._get_called_functions(self.functions)
        # TODO: filter out external functions -> consider adding a filter to the
        # get_called_functions method (this might cover the globals too)

        # TODO2: when do we need to call get_function_stats?
        # do we need to call it with self.functions as the second arg?
        # what would be the best way to create a filter for internal/external

        self.cutoff._get_function_stats(function_ids, self.functions)
        # after calling get_function_stats the list of external funcs can be found in
        # self.external_funcs and the list of internal funcs can be found in self.internal_funcs

        self.globals = set()
        all_types = set()
        internal_defs = set()
        _funcs = set()
        _funcs |= self.cutoff.internal_funcs
        _funcs |= self.cutoff.external_funcs
        self.deps._discover_functions_and_globals(
            _funcs, self.globals, all_types, basedirs, internal_defs)
        self.dbops.all_funcs_with_asm = all_funcs_with_asm_copy

        logging.debug("funcs are " + str(self.functions))
        self.cutoff._get_function_stats(function_ids, _funcs)
        # after calling get_function_stats the list of external funcs can be found in
        # self.external_funcs and the list of internal funcs can be found in self.internal_funcs
        self.functions |= _funcs
        logging.info("Engine found " +
                     str(len(self.functions)) + " functions")

        if self.cut_off != CutOff.CUT_OFF_NONE:
            # TODO: now I'm going to repeat some steps from above, but the filtering could be
            # done in a more efficient way

            # if self.func_stats == Generator.FUNC_STATS_DETAILED and self.external_inclusion_margin > 0:
            if self.external_inclusion_margin > 0:
                # let's see which of the external functions could be included
                included = set()
                new_external = set()
                for f_id in self.cutoff.external_funcs:
                    if f_id in self.cutoff.stats_cache:
                        # please note that self.stats_cache will be filled if we executed
                        # _get_function_stats (partially for basic stats, full for detailed)
                        # if the id is found in cache we will immediately know how many functions does
                        # the function pull in
                        # -1 as the function is included there as well
                        count = len(self.cutoff.stats_cache[f_id]) - 1
                        if count < self.external_inclusion_margin:
                            # external function pulls in no more than a threshold of other functions
                            # let's make them all internal then
                            _included = set(self.cutoff.stats_cache[f_id])
                            if not self.include_asm:
                                _included = set(
                                    [id for id in _included if id not in self.dbops.all_funcs_with_asm])

                            self.cutoff.internal_funcs |= _included
                            included |= _included
                            # stats_cache only takes into account functions and not funcdecls
                            # since we include a function / list of functions we need to check if
                            # some of the funcdecls they call might need to be added to external
                            # funcs
                            for f in _included:
                                func = self.dbops.fnidmap[f]
                                if not func:
                                    continue
                                for ref in func["funrefs"]:
                                    if ref in self.dbops.fdmap or ref in self.dbops.umap:
                                        # found a reference that is either func decl or unresolved
                                        new_external.add(ref)

                self.cutoff.external_funcs.difference_update(included)
                self.cutoff.external_funcs |= new_external
                logging.info(f"Included {len(included)} functions")
                logging.info(
                    f"Now we have {len(self.cutoff.internal_funcs)} internal and {len(self.cutoff.external_funcs)} external")

            # TODO: for now I will also filter out as external all the functions with inline assembly
            # perhaps in the future there is a better way to handle those
            # removed = set()
            for f_id in self.cutoff.internal_funcs:
                f = self.dbops.fnidmap[f_id]
                if f is not None:
                    if not self.include_asm and self.dbops._func_contains_assembly(f):
                        self.cutoff.external_funcs.add(f_id)
                        logging.info(
                            f'Function {f["name"]} contains inline assembly - will treat it as external')
            self.globals = set()
            self.internal_defs = set()
            for f in function_ids:
                self.functions.add(f)

            # we have to add the main functions we focus on
            for f in function_ids:
                self.cutoff.internal_funcs.add(f)

            # just in case: filter out known functions
            self.deps._discover_known_functions(self.cutoff.internal_funcs)
            self.cutoff.internal_funcs = self.deps._filter_out_known_functions(
                self.cutoff.internal_funcs)
            self.deps._discover_known_functions(self.cutoff.external_funcs)
            self.cutoff.external_funcs = self.deps._filter_out_known_functions(
                self.cutoff.external_funcs)

            # at this point we alredy know which functions are internal and which are external;
            # however, we don't know which globals should be pulled in by the internal functions -> that is what
            # we're going to learn next

            # let's operate on a copy of internal_funcs, just in case
            internals = set(self.cutoff.internal_funcs)
            all_types = set()
            self.deps._discover_functions_and_globals(
                internals, self.globals, all_types, basedirs, internal_defs)
            logging.info(
                f"functions size is {len(self.functions)}, external functions size is {len(self.cutoff.external_funcs)} internal funcs size is {len(self.cutoff.internal_funcs)} known funcs size is {len(self.dbops.known_funcs_ids)}")

            # if len(internals) != len(self.internal_funcs):

            # sys.exit(1)
        else:
            # we don't need to to cut off any functions
            # TODO: currently the list of internal/external is established in the _get_function_stats function
            # and only based on the module -> that needs to be parametrized
            self.cutoff.internal_funcs = self.functions
            self.cutoff.external_funcs = set()


        # we need to know: all funcs, all globals and all types
        # types are necessary in order to discover if they don't contain references to globals
        # globals, in turn, could reference other globals and functions

        # Once we have all functions we need to generate separate files
        # that mimic the original spread of functions.
        # The split into files is required as some of types might collide:
        # e.g. an unnamed enum might be defined multiple
        # times and those definitions cannot co-exist in the same source file.
        # Once we have multiple files we get all the types required in each file.

        # files:
        # keys = file ids
        # values = lists of function names belonging to a file
        files = {}
        # we need to keep track of which of the functions we would like to call
        # are static and where are they located
        static_files = {}
        static_functions = {}
        self.static_and_inline_funcs = {}

        for func in self.cutoff.internal_funcs:
            function = self.dbops.fnidmap[func]
            if function is None:
                logging.warning("Function {} not found. Trying funcdecl.".format(func))
                # TODO: handle funcdelcs
                function = self.dbops.fdmap[func]
                if function is None:
                    logging.error("Function {} not found".format(func))
                    continue
            fid = function["fid"]

            if ("fids" in function) and (len(function["fids"]) > 1) and (func not in function_ids) and function["linkage"] == "internal":
                self.static_and_inline_funcs[func] = function["fids"]
                continue

            if fid not in files:
                files[fid] = File()
            files[fid].funcs.append(func)
            if function["linkage"] == "internal" and func in function_ids:
                if fid not in static_files:
                    static_files[fid] = File()
                static_files[fid].funcs.append(func)
                static_functions[func] = fid

            logging.debug("Function {} matched with file {}".format(func, fid))

        # handle external funcs
        stub_files = {}
        for func in self.cutoff.external_funcs:
            function = self.dbops.fnidmap[func]
            if function is None:
                logging.warning("Function {} not found. Trying funcdecl.".format(func))
                # TODO: handle funcdelcs
                function = self.dbops.fdmap[func]
                if function is None:
                    logging.error("Function {} not found".format(func))
                    continue
            if ("fids" in function) and (len(function["fids"]) > 1) and (func not in function_ids) and function["linkage"] == "internal":
                self.static_and_inline_funcs[func] = function["fids"]
            fid = function["fid"]
            if fid not in stub_files:
                stub_files[fid] = File()
            stub_files[fid].funcs.append(func)

            # external static functions need to be present in the corresponding files
            # as well
            if function["linkage"] == "internal":
                if fid not in files:
                    files[fid] = File()
                    files[fid].funcs.append(func)
                elif func not in files[fid].funcs:
                    files[fid].funcs.append(func)
        files_for_globals = 0
        for glob in self.globals:
            g = self.dbops.globalsidmap[glob]

            # loc_index = g["location"].find(":")
            # loc = g["location"][:loc_index]
            # logging.info("loc is {}".format(loc))
            fid = g["fid"]
            logging.debug("fid is {}".format(fid))
            if fid not in files:
                files[fid] = File()
                files_for_globals += 1
            files[fid].globals.append(glob)

        # once we have all the files
        # handle static and inline functions
        for func in self.static_and_inline_funcs:
            additional = set()
            f = self.dbops.fnidmap[func]
            if f is not None:
                f_id = f["id"]
                if f_id in self.dbops.static_funcs_map:
                    additional = self.dbops.static_funcs_map[f_id]
            fids = set(self.static_and_inline_funcs[func])

            prev = len(fids)
            fids |= additional
            if prev != len(fids):
                logging.info("workardound working: we have more fids now")

            for fid in fids:
                if fid in files and func not in files[fid].funcs:
                    logging.info("Adding func {} to file {}".format(func, fid))
                    files[fid].funcs.append(func)

        for f_id in self.cutoff.internal_funcs:
            if f_id in self.dbops.known_funcs_ids:
                self.deps.known_funcs_present.add(
                    self.dbops._get_function_name(f_id))
        for f_id in self.cutoff.external_funcs:
            if f_id in self.dbops.known_funcs_ids:
                self.deps.known_funcs_present.add(
                    self.dbops._get_function_name(f_id))
        for f_id in self.static_and_inline_funcs:
            if f_id in self.dbops.known_funcs_ids:
                self.deps.known_funcs_present.add(
                    self.dbops._get_function_name(f_id))
        self.otgen.adjust_funcs_lib()

        logging.info("We have {} distinct files".format(len(files)))

        # once we know all the internal functions, let's gather some info on pointer sizes
        _funcs = set()
        _funcs |= self.cutoff.internal_funcs
        _funcs |= set(self.static_and_inline_funcs.keys())
        _funcs.difference_update(self.cutoff.external_funcs)
        _funcs = self.deps._filter_out_known_functions(_funcs)
        _funcs = self.deps._filter_out_builtin_functions(_funcs)
        _types = set()
        _types |= all_types
        _types |= internal_defs
        _internal_defs = set()

        _t, _d = self.deps._get_types_recursive(
            _types, internal_defs=_internal_defs)
        _types |= set(_t)
        _types |= _internal_defs
        _funcs = self.dbops.fnidmap.get_many(_funcs)
        _types = self.deps._remove_duplicated_types(_types)
        _types = self.dbops.typemap.get_many(_types)
        self.init._generate_member_size_info(_funcs, _types)
        # self._print_member_size_info()
        # for each file, get the types needed by the functions in that file/
        # generate a corresponding source file
        sources = []
        fileno = len(files)
        logging.info("Going to generate {} source files".format(fileno))
        i = 1
        includes = []
        if self.libc_includes:
            # C standard library includes, after
            # https://en.cppreference.com/w/c/header
            includes = ['<assert.h>',
                        '<complex.h>',
                        '<ctype.h>',
                        '<errno.h>',
                        '<fenv.h>',
                        '<float.h>',
                        '<inttypes.h>',
                        '<iso646.h>',
                        '<limits.h>',
                        '<locale.h>',
                        '<math.h>',
                        '<setjmp.h>',
                        '<signal.h>',
                        '<stdalign.h>',
                        '<stdarg.h>',
                        '<stdatomic.h>',
                        '<stdbool.h>',
                        '<stddef.h>',
                        '<stdint.h>',
                        '<stdio.h>',
                        '<stdlib.h>',
                        '<stdnoreturn.h>',
                        '<string.h>',
                        '<tgmath.h>',
                        # '<threads.h>',
                        '<time.h>',
                        '<uchar.h>',
                        '<wchar.h>',
                        '<wctype.h>']

        # before we generate all source files, let's generate headers containing
        # static inline functions
        self.otgen._generate_static_inline_headers(
            set(self.static_and_inline_funcs.keys()))

        all_global_ids = set()
        filename_to_fid = {}
        for fid, file in files.items():
            logging.info("Generating file {} of {}".format(i, fileno))
            i += 1
            funcs = file.funcs
            globs = file.globals

            for id in self.otgen.static_inline_headers:
                if id in funcs:
                    funcs.remove(id)

            if len(funcs) == 0 and len(globs) == 0:
                logging.info("This file is empty: skipping")
                continue
            logging.info(
                f"funcs number {len(funcs)} globs number {len(globs)}, funcs are {funcs}")
            filename = ""
            # generate source file
            if fid in static_files:
                str_header, str_file, filename, func_ids, globals_ids, types, internal_defs = self.otgen._create_src_file(
                    fid, funcs, globs, includes, static_files[fid].funcs)
                all_global_ids |= globals_ids
                self.otgen.set_fid_to_filename(fid, filename)
                self.sources_to_types[filename] = types
                self.file_contents[filename] = str_file
                filename_to_fid[filename] = int(fid)
                static_files[fid].types = types
                static_files[fid].filename = filename
                static_files[fid].globals = globals_ids
                static_files[fid].funcs = func_ids
            else:
                str_header, str_file, filename, func_ids, globals_ids, types, internal_defs = self.otgen._create_src_file(
                    fid, funcs, globs, includes, [])
                all_global_ids |= globals_ids
                self.otgen.set_fid_to_filename(fid, filename)
                self.sources_to_types[filename] = types
                self.file_contents[filename] = str_file
                filename_to_fid[filename] = int(fid)
                files[fid].types = types
                files[fid].filename = filename
                files[fid].globals = globals_ids
                files[fid].funcs = func_ids
            sources.append(filename)

        self.cutoff.external_funcs = self.deps._filter_out_builtin_functions(
            self.cutoff.external_funcs)
        for fid, file in stub_files.items():
            funcs_copy = file.funcs.copy()
            for f_id in file.funcs:
                if f_id in self.otgen.static_inline_headers:
                    funcs_copy.remove(f_id)
            if len(funcs_copy) == 0:
                logging.info("This stub file is empty: skipping")
                continue
            str_header, str_file, filename, func_ids, globals_ids, types, internal_defs = self.otgen._create_src_file(
                f'{fid}', funcs_copy, [], [], [], stubs=True)
            self.sources_to_types[filename] = types
            self.file_contents[filename] = str_file
            filename_to_fid[filename] = int(fid)
            all_global_ids |= globals_ids
            sources.append(filename)
            stub_files[fid].types = types
            stub_files[fid].filename = filename
            stub_files[fid].globals = globals_ids
            stub_files[fid].funcs = func_ids

        if all([f_name.partition('@')[0] != "main"
                for f_name in function_names]):
            # if "main" is not among the functions of interest
            # we need to generate it ourselves
            # TODO: always generate test driver - it will be necessary to
            # introduce instrumentation
            sources.append("aot.c")

            # we will need to generate all type, function and global data which is necessary

            str_header, str_file, filename, globals_ids, types, internal_defs = self.otgen._create_test_driver(
                function_ids, static_functions, all_global_ids)
            self.sources_to_types[filename] = types
            self.file_contents[filename] = str_file

            # generate data init for the static globals
            known_type_names = set()
            for t_id in types:
                t = self.dbops.typemap[t_id]
                if t["class"] == "record":
                    known_type_names.add(t["str"])

            logging.info(f"known type names are {known_type_names}")
            new_types = set()
            _str = ""
            contents_to_change = {}
            filename_to_fpointer_stubs = {}
            for g_id in all_global_ids:
                self.init.fpointer_stubs = []
                g = self.dbops.globalsidmap[g_id]
                if self.dump_global_hashes:
                    gmodule = ''
                    if len(g["mids"]) == 0:
                        logging.warning("Global '{0}' belongs to the unknown module (.mids is empty)".format(g["name"]))
                    else:
                        if len(g["mids"]) > 1:
                            logging.warning("Global '{0}' has multiple entries in .mids section. The first one from the list (random) will be used".format(g["name"]))
                        gmodule = self.dbops.modidmap[g["mids"][0]].split('/')[-1]
                    self.global_hashes.append((str(g["hash"]),g["fid"],gmodule))
                glob_has_init = g['hasinit']
                # one more check: sometimes globals are pointers initialized to null
                g_tid = g["type"]
                g_t = self.dbops.typemap[g_tid]
                g_t = self.dbops._get_typedef_dst(g_t)
                if g_t["class"] == "pointer":
                    initstr = g["init"]
                    if initstr == "((void *)0)":
                        glob_has_init = False
                
                # # enforcing initialization of globals
                # if g_t["class"] != "const_array":
                #     glob_has_init = False
                if not glob_has_init and g["linkage"] == "internal" or len(g_t["str"]) == 0:
                    # get id of the global definition file
                    g_fid = g["fid"]
                    filename = self.otgen.fid_to_filename[g_fid]

                    pointers = []
                    self.recursion_fuse = 0
                    init_obj = None
                    if self.smart_init:
                        param_tid, init_obj = self.otgen.globs_init_data[g['id']]

                    tmp_str, alloc, brk = self.init._generate_var_init(
                        g["name"], self.dbops.typemap[g["type"]], "", pointers, known_type_names=known_type_names, new_types=new_types,
                        entity_name=g['name'], fuse=0, init_obj=init_obj)
                    if filename not in contents_to_change:
                        contents_to_change[filename] = ""
                    contents_to_change[filename] += tmp_str

                    if len(self.init.fpointer_stubs):
                        if filename not in filename_to_fpointer_stubs:
                            filename_to_fpointer_stubs[filename] = []
                        for stub in self.init.fpointer_stubs:
                            filename_to_fpointer_stubs[filename].append(stub)

            for filename in contents_to_change:
                contents = self.file_contents[filename]
                _str = contents_to_change[filename]
                if len(_str) > 0:
                    _str = _str.replace("\n", "\n\t")
                    contents = contents.replace(
                        OTGenerator.AOT_STATIC_GLOBS_MARKER, _str)
                    if filename in filename_to_fpointer_stubs:
                        _str = ""
                        stubs = filename_to_fpointer_stubs[filename]
                        for stub in stubs:
                            _str += f"{stub}\n\n"
                        contents = contents.replace(
                            OTGenerator.AOT_STATIC_GLOBS_FPTRS, _str)
                    self.file_contents[filename] = contents

            self.deps.capture_literals(
                all_global_ids, self.cutoff.internal_funcs)

        # let's generate a universal header
        # this header contains all necessary declarations and definitions for all types

        # first, let's figure out which functions, globals and types might need to be included conditionally
        # note: this only applies if there is a name clash: the same name means something different in different TUs
        # types go first

        logging.info("Looking for type name clashes")
        type_clashes = set()
        type_names = set()
        name_to_tids = {}
        tclashes = set()
        for t_id in self.otgen.all_types:
            if t_id in tclashes:
                continue

            t = self.dbops.typemap[t_id]
            name = t["str"]
            cl = t["class"]
            if cl == "typedef":
                name = t["name"]

            if len(name) > 0:
                type_names.add(name)
                if name not in name_to_tids:
                    name_to_tids[name] = []
                name_to_tids[name].append(t_id)

            identifiers = set()
            if cl == "enum":
                # a special case of enums: we will detect clashes by looking at the values
                identifiers = set(t["identifiers"])
            elif len(name) == 0 or name == "*" or name == "typedef" or name == "[N]" or name == "()" or name == "[]":
                continue

            if cl == "record_forward":
                # no need to ifdef record fwd
                continue
            for t_id2 in self.otgen.all_types:
                if t_id == t_id2:
                    continue

                t2 = self.dbops.typemap[t_id2]
                name2 = t2["str"]
                cl2 = t2["class"]
                if cl2 == "typedef":
                    name2 = t2["name"]

                identifiers2 = set()
                if cl2 == "enum":
                    identifiers2 = set(t2["identifiers"])

                match = False

                if cl == "enum":
                    if cl2 != "enum" and len(name) > 0:
                        if name == name2:
                            match = True
                    elif cl2 == "enum":
                        if len(identifiers) > 0 and len(identifiers2) > 0 and len(identifiers.intersection(identifiers2)) != 0:
                            match = True
                else:
                    if name == name2:
                        match = True

                if match:
                    # make sure we are not dealing with a type duplicate (same type but with const)
                    if t_id in self.deps.dup_types and t_id2 in self.deps.dup_types[t_id]:
                        continue

                    if cl2 == "record_forward":
                        # no need to ifdef record fwd
                        continue

                    if cl == "typedef":
                        if t["refs"][0] == t_id2:
                            continue
                        if t_id2 in self.deps.dup_types and t["refs"][0] in self.deps.dup_types[t_id2]:
                            continue
                    if cl2 == "typedef":
                        if t2["refs"][0] == t_id:
                            continue
                        if t_id in self.deps.dup_types and t2["refs"][0] in self.deps.dup_types[t_id]:
                            continue

                    # we've found a name clash right here
                    type_clashes.add((t_id2, t_id))
                    tclashes.add(t_id)
                    tclashes.add(t_id2)
                    logging.debug(f"adding types to clash: {t_id2}, {t_id}")
        logging.info(
            f"We've found {len(type_clashes)} clashing types: {type_clashes}")

        logging.info("Looking for global name clashes")
        global_clashes = set()
        global_names = set()
        name_to_gids = {}
        gclashes = set()
        for g_id in all_global_ids:
            if g_id in gclashes:
                continue

            name = self.dbops.globalsidmap[g_id]["name"]
            if len(name) == 0:
                continue

            global_names.add(name)
            if name not in name_to_gids:
                name_to_gids[name] = []
            name_to_gids[name].append(g_id)

            for g_id2 in all_global_ids:
                if g_id == g_id2:
                    continue
                name2 = self.dbops.globalsidmap[g_id2]["name"]
                if name == name2:
                    # we've found a name clash right here
                    global_clashes.add((g_id2, g_id))
                    gclashes.add(g_id)
                    gclashes.add(g_id2)
        logging.info(f"We've found {len(global_clashes)} clashing globals")

        self.otgen.all_funcs |= set(self.static_and_inline_funcs.keys())

        logging.info("Looking for function name clashes")
        function_clashes = set()
        func_names = set()
        name_to_fids = {}
        fclashes = set()
        for f_id in self.otgen.all_funcs:
            if f_id in fclashes:
                continue

            if f_id in self.dbops.fnidmap:
                name = self.dbops.fnidmap[f_id]["name"]
            elif f_id in self.dbops.fdmap:
                name = self.dbops.fdmap[f_id]["name"]
            else:
                name = self.dbops.umap[f_id]["name"]

            if len(name) == 0:
                continue

            func_names.add(name)
            if name not in name_to_fids:
                name_to_fids[name] = []
            name_to_fids[name].append(f_id)

            for f_id2 in self.otgen.all_funcs:
                if f_id == f_id2:
                    continue

                if f_id2 in self.dbops.fnidmap:
                    name2 = self.dbops.fnidmap[f_id2]["name"]
                elif f_id2 in self.dbops.fdmap:
                    name2 = self.dbops.fdmap[f_id2]["name"]
                else:
                    name2 = self.dbops.umap[f_id2]["name"]
                if name == name2:
                    # we've found a name clash right here
                    function_clashes.add((f_id2, f_id))
                    fclashes.add(f_id)
                    fclashes.add(f_id2)
        logging.info(
            f"We've found {len(function_clashes)} clashing functions: {function_clashes}")

        func_glob_clashes = set()
        # global names can clash with function names
        intersection = global_names.intersection(func_names)
        if len(intersection) > 0:
            # there are some types clashes of type and global names
            for name in intersection:
                fids = name_to_fids[name]
                gids = name_to_gids[name]
                for f_id in fids:
                    for g_id in gids:
                        func_glob_clashes.add((f_id, g_id))

        # now since we know which functions, types and globals are clashing
        # lets find out in which files they are used
        all_files = set()
        all_files |= set(files.keys())
        all_files |= set(static_files.keys())
        all_files |= set(stub_files.keys())

        for f_id, fids in self.static_and_inline_funcs.items():
            final_fids = set(fids)
            final_fids.intersection_update(all_files)

            for fid in final_fids:
                if fid not in files:
                    files[fid] = File()
                if isinstance(files[fid].funcs, list):
                    files[fid].funcs.append(f_id)
                else:
                    files[fid].funcs.add(f_id)

        logging.info("find clashes in files")
        self.deps._find_clashes(files, type_clashes,
                                global_clashes, function_clashes, func_glob_clashes)
        logging.info("find clashes in static files")
        self.deps._find_clashes(static_files, type_clashes,
                                global_clashes, function_clashes, func_glob_clashes)
        logging.info("find clashes in stub files")
        self.deps._find_clashes(stub_files, type_clashes,
                                global_clashes, function_clashes, func_glob_clashes)

        logging.info(
            f"Clash data: type to file {len(self.deps.clash_type_to_file)} items, global to file {len(self.deps.clash_global_to_file)} items, func to file {len(self.deps.clash_function_to_file)} items")


        # self.include_std_headers = [ f"<{h}>" for h in self.include_std_headers ]
        str_header, str_file, filename, func_ids, globals_ids, types, internal_defs = self.otgen._create_src_file(
            OTGenerator.AOT_HEADER_ID, self.otgen.all_funcs, all_global_ids, [], static_functions, create_header=True)
        if self.dynamic_init:
            str_header += "\n\n// Global initializers fwd decls"
            for f in self.otgen.global_trigger_name_list:
                str_header += f"\nvoid init_{f}();"
                

        str_header += "\n#endif"
        self.otgen._store_item_in_header(OTGenerator.AOT_HEADER, str_header)

        # we take the Makefile from resources directory

        # store file contents to disk
        real_names = set()
        base_files = [ "aot.c", "aot.h" ]
        for filename in self.file_contents:
            contents = self.file_contents[filename]
            dst_filename = filename
            if self.use_real_filenames and filename not in base_files:
                fid = filename_to_fid[filename]
                
                real_name = os.path.basename(self.dbops.srcidmap[fid])
                if "_stub" in filename:
                    suffix = real_name[real_name.rfind("."):]
                    real_name = real_name[:real_name.rfind(".")] + "_stub" + suffix
                
                suffix_index = real_name.rfind(".")
                suffix = real_name[suffix_index:]
                real_name = real_name[:suffix_index] + f"_{fid}" + suffix
                

                if real_name in real_names:
                    i = 2
                    tmp = real_name
                    while (tmp in real_names):
                       tmp = f"{i}_{real_name}"
                       i += 1
                    real_name = tmp
                    real_names.add(real_name)
                else:
                    real_names.add(real_name)
                dst_filename = real_name
                del filename_to_fid[filename]
                filename_to_fid[dst_filename] = fid

            with open(f"{self.out_dir}/{dst_filename}", "a+") as file:
                file.write(contents)
        
        with open(f"{self.out_dir}/file_to_fid.json", "w") as file:
            json.dump(filename_to_fid, file)

        # try to pretty-print the files
        clang_format = shutil.which("clang-format")
        if clang_format is not None:
            logging.info("Will format files with clang-format")
            to_format = ['aot.c']
            for filename in to_format:
                subprocess.run(
                    ["clang-format", "-i", f"{self.out_dir}/{filename}"])

        logging.info("Output generated in " + self.out_dir)
        logging.info(f"AOT_OUT_DIR: {os.path.abspath(self.out_dir)}\n")
        if self.smart_init and self.dump_smart_init:
            types = self.dbops.typemap.get_many(self.otgen.all_types)
            # out_name = "smart_init.json"
            # logging.info(f"As requested, dumping the smart init data to a JSON file {out_name}")
            for t in types:
                entry, single_init, offset_types = self.init._get_cast_ptr_data(t)
                if entry is not None or offset_types is not None:
                    logging.info(
                        f"Data init for type {t['id']}: {entry}, {offset_types}")
                for i in range(len(t['refs'])):
                    #                   if t['usedrefs'][i] != -1:
                    entry, single_init, offset_types = self.init._get_cast_ptr_data(
                        t, i)
                    if entry is not None or offset_types is not None:
                        logging.info(
                            f"Data init for type {t['id']}, member {i}: {entry}, {offset_types}")

        tmp = "\n#### STATS ####\n"
        tmp += "Files count: AOT_FILES_COUNT: {}\n".format(
            len(self.otgen.stats))
        self.otgen.all_types = self.deps._remove_duplicated_types(
            self.otgen.all_types)

        tmp += "Types count: AOT_TYPES_COUNT: {}\n".format(
            len(self.otgen.all_types))
        struct_types = 0
        t_no_dups = self.dbops.typemap.get_many(self.otgen.all_types)
        for t in t_no_dups:
            if t["class"] == "record":
                struct_types += 1

        tmp += "Struct types count: AOT_STRUCT_TYPES_COUNT: {}\n".format(
            struct_types)
        tmp += "Globals count: AOT_GLOBALS_COUNT: {}\n".format(
            len(all_global_ids))

        self.cutoff.internal_funcs.difference_update(
            self.cutoff.external_funcs)
        self.cutoff.internal_funcs = self.deps._filter_out_known_functions(
            self.cutoff.internal_funcs)
        self.cutoff.internal_funcs = self.deps._filter_out_builtin_functions(
            self.cutoff.internal_funcs)
        self.cutoff.external_funcs = self.deps._filter_out_known_functions(
            self.cutoff.external_funcs)
        self.cutoff.external_funcs = self.deps._filter_out_builtin_functions(
            self.cutoff.external_funcs)
        tmp += "Funcs count: AOT_INT_FUNCS_COUNT: {}\n".format(
            len(self.cutoff.internal_funcs))
        tmp += "Funcs count: AOT_EXT_FUNCS_COUNT: {}\n".format(
            len(self.cutoff.external_funcs))
        logging.info("{}".format(tmp))
        if len(self.codegen.funcs_with_asm) > 0:
            tmp = "\n# WARNING: the functions below have inline assembly commented out:\n"
            for fid, data in self.codegen.funcs_with_asm.items():
                f = self.dbops.fnidmap[fid]
                file = data["file"]
                diff = data["diff"]
                tmp += f'[{file}] : {f["name"]}\n'

        logging.info("{}".format(tmp))
        logging.info(
            f"functions size is {len(self.functions)}, external functiosn size is {len(self.cutoff.external_funcs)} internal funcs size is {len(self.cutoff.internal_funcs)}")
        # logging.info("all funcs")
        # for f in self.all_funcs:
        #    logging.info(self.dbops._get_function_name(f))
        # logging.info("external funcs")
        # for f in self.external_funcs:
        #    logging.info(self.dbops._get_function_name(f))
        # logging.info("internal funcs")
        # for f in self.internal_funcs:
        #    logging.info(self.dbops._get_function_name(f))
        # logging.info("functions")
        # for f in self.functions:
        #     logging.info(f"{self.dbops._get_function_name(f)}")

        logging.info(
            f"genrated functions {self.codegen.generated_functions}, generated stubs {self.codegen.generated_stubs}")
        logging.info(
            f"generated {files_for_globals} files for globals and {len(self.globals)} globals")
        logging.info(
            f"Stubs returning a pointer are mapped to the following return addresses:")
        for s in self.codegen.stub_to_return_ptr:
            if self.include_asm or s not in self.codegen.stubs_with_asm:
                # by a 'bucket' we mean the range within which the stub-generated value falls
                bucket = (
                    self.codegen.stub_to_return_ptr[s] - CodeGen.AOT_SPECIAL_PTR) // CodeGen.AOT_SPECIAL_PTR_SEPARATOR // 2
                logging.info(
                    f"AOT_STUB_MAPPING{bucket}:{s}:{hex(self.codegen.stub_to_return_ptr[s] - CodeGen.AOT_SPECIAL_PTR_SEPARATOR)}:{hex(self.codegen.stub_to_return_ptr[s] + CodeGen.AOT_SPECIAL_PTR_SEPARATOR)}")

        if self.verify_struct_layout:
            logging.info(
                f"Generating code to verify layout of generated struct types in {self.out_dir}/{CodeGen.VERIFY_STRUCT_LAYOUT_SOURCE}")
            verify_recipes = self.codegen._generate_verification_recipes()
            with open(os.path.join(self.out_dir, CodeGen.VERIFY_STRUCT_LAYOUT_TEMPLATE), "rt") as f:
                template_out = f.read()
            with open(os.path.join(self.out_dir, CodeGen.VERIFY_STRUCT_LAYOUT_SOURCE), "wt") as f:
                f.write(template_out % ("\n".join(verify_recipes)))

        if self.dump_global_hashes:
            logging.info(
                f"Saving hashes of global variables used into {self.out_dir}/{Engine.GLOBAL_HASH_FILE}")
            with open(f"{self.out_dir}/{Engine.GLOBAL_HASH_FILE}", "w") as file:
                file.write("\n".join(["%s %d %s"%(x[0],x[1],x[2]) for x in self.global_hashes]))

        if self.dump_ids:
            ids_dump = {}
            ids_dump["types"] = list(self.otgen.all_types)
            ids_dump["globals"] = list(all_global_ids)
            ids_dump["entry_funcs"] = list(self.function_names)
            ids_dump["int_funcs"] = list(self.cutoff.internal_funcs)
            ids_dump["ext_funcs"] = list(self.cutoff.external_funcs)
            with open(f"{self.out_dir}/ids.json", "w") as dump_file:
                json.dump(ids_dump, dump_file)

        if self.dynamic_init:
            logging.info(f"Creating files required for dynamic initialization")
            # TODO: this should be handled by resource manager
            # copy the predefined files required for dynamic initialization
            predefined_files_dyn_init = ["dyn_init.c", "dyn_init.h"]
            res_dir = os.path.join(os.path.dirname(__file__), "resources")
            for f in predefined_files_dyn_init:
                shutil.copyfile(f"{res_dir}/{f}", f"{self.out_dir}/{f}")
                shutil.copymode(f"{res_dir}/{f}", f"{self.out_dir}/{f}")

            with open(os.path.join(res_dir, Engine.FUNCTION_POINTER_STUB_FILE_TEMPLATE), "rt") as f:
                fptrstub_out = f.read()
            with open(os.path.join(self.out_dir, Engine.FUNCTION_POINTER_STUB_FILE_SOURCE), "wt") as f:
                fstub_decls_out = "\n".join(["extern int (*%s)(void);" % (fstub)
                                            for fstub, fstub_id in self.codegen.function_pointer_stubs])
                fstubs_out = "\n".join(["  { \"%s\", 0 }," % (
                    fstub) for fstub, fstub_id in self.codegen.function_pointer_stubs])
                fstubs_init = "\n".join(["  fptrstub_pair_array[%d].address = %s;" % (
                    i, fstubT[0]) for i, fstubT in enumerate(self.codegen.function_pointer_stubs)])
                flib_stubs = "\n".join(
                    ["%s" % (flibstub) for flibstub, flibstub_id in self.codegen.lib_function_pointer_stubs])
                fstub_init_decls = "\n".join([f" __attribute__((weak)) void init_{x}() {{}}" for x in self.otgen.global_trigger_name_list])
                fstubs_init_call = "\n".join([f"  init_{x}();" for x in self.otgen.global_trigger_name_list])
                f.write(fptrstub_out % (fstub_init_decls, fstub_decls_out, len(
                    self.codegen.function_pointer_stubs), fstubs_out, fstubs_init, fstubs_init_call, flib_stubs))

            with open(os.path.join(res_dir, Engine.FUNCTION_POINTER_KNOWN_FUNCS_STUB_FILE_TEMPLATE), "rt") as f:
                fptrstub_known_funcs_out = f.read()
            with open(os.path.join(self.out_dir, Engine.FUNCTION_POINTER_KNOWN_FUNCS_STUB_FILE_SOURCE), "wt") as f:
                known_funcs_decls = list()
                known_funcs_stub_list = list()
                used_fstubs = set(
                    [fstub_id for fstub, fstub_id in self.codegen.function_pointer_stubs])
                used_lib_fstubs = set(
                    [fstub_id for fstub, fstub_id in self.codegen.lib_function_pointer_stubs])
                for f_id in self.dbops.known_funcs_ids:
                    function = self.dbops.fnidmap[f_id]
                    if function and function["linkage"] != "internal" and function["id"] in used_fstubs and function["id"] not in used_lib_fstubs:
                        known_funcs_stub_list.append(
                            self.codegen._get_function_pointer_stub(function))
                        known_funcs_decls.append(function["declbody"]+";")
                f.write(fptrstub_known_funcs_out % (
                    "\n".join(known_funcs_decls), "\n".join(known_funcs_stub_list)))

        return True

    # -------------------------------------------------------------------------

    # @belongs: engine

    def _sanity_check(self, args):
        if args.known_funcs_file and not os.path.isfile(args.known_funcs_file):
            logging.error(
                f"File with known functions not found {args.known_funcs_file}")
            return False

        if args.lib_funcs_file and not os.path.isfile(args.lib_funcs_file):
            logging.error(
                f"File with library functions not found {args.lib_funcs_file}")
            return False

        if args.always_inc_funcs_file and not os.path.isfile(args.always_inc_funcs_file):
            logging.error(
                f"File with always included functions not found {args.always_inc_funcs_file}")
            return False

        return True

# ------------------------------------------------------------------------------


def prepare_parser(*db_frontends):
    parser = argparse.ArgumentParser(
        description='Auto off-target generator: "Select a function, generate a program, test a subsystem®"', conflict_handler="resolve")

    for db_frontend in db_frontends:
        db_frontend.parse_args(parser)
    parser.add_argument('--config',
                        default=None,
                        help='The path to config file')
    parser.add_argument('--product',
                        default=None,
                        required=True,
                        help='Product name, e.g. kernel')
    parser.add_argument('--version',
                        default=None,
                        required=True,
                        help='Product version, e.g. 5.18')
    parser.add_argument('--build-type',
                        default='eng',
                        choices=['eng', 'user', 'engdebug', 'userdebug'],
                        required=True,
                        help='Product version, e.g. eng')

    parser.add_argument('--db',
                        default=None,
                        help='Path to a *.img database file to load')

    parser.add_argument('--functions', nargs="+", default="",
                        help='list of functions to generate off-target for; in order to specify ' +
                             'a file please use the following syntax: function_name@file_name')
    parser.add_argument('--output-dir', default=Engine.DEFAULT_OUTPUT_DIR,
                        help="A path to the output directory (default: {})".format(Engine.DEFAULT_OUTPUT_DIR))
    co_help = 'select cut-off algorithm: ' +\
              '{} - do not cut off anything, ' +\
              '{} - cut off everything outside off-traget function\'s module, ' +\
              '{} - cut off everything outside of the functions list (see the --co-funcs param), ' +\
              '{} - cut off everything outside of the specified directories (see the --co-dirs param), ' +\
              '{} - cut off everything outside of the specified files (see the --co-files param), ' +\
              '{} - cut off everythong outside of the specified modules (see the -co-modules param)'
    co_help = co_help.format(
        CutOff.CUT_OFF_NONE, CutOff.CUT_OFF_FUNCTIONS, CutOff.CUT_OFF_MODULE,
        CutOff.CUT_OFF_DIRS, CutOff.CUT_OFF_FILES, CutOff.CUT_OFF_NAMED_MODULES)
    parser.add_argument('--cut-off', choices=[CutOff.CUT_OFF_NONE, CutOff.CUT_OFF_FUNCTIONS, CutOff.CUT_OFF_MODULE,
                                              CutOff.CUT_OFF_DIRS, CutOff.CUT_OFF_FILES, CutOff.CUT_OFF_NAMED_MODULES],
                        default=CutOff.CUT_OFF_MODULE,
                        help=co_help)
    parser.add_argument('--co-funcs', nargs="+", default="",
                        help='a list of functions for use with the --cut-off option')
    parser.add_argument('--co-dirs', nargs="+", default="",
                        help='a list of directories for use with the --cut-off option')
    parser.add_argument('--co-modules', nargs="+", default="",
                        help='a list of modules for use with the --cut-off option')
    parser.add_argument('--co-files', nargs="+", default="",
                        help='a list of files for use with the --cut-off option')

    parser.add_argument('--func-stats', choices=[CutOff.FUNC_STATS_NONE, CutOff.FUNC_STATS_BASIC, CutOff.FUNC_STATS_DETAILED],
                        default=CutOff.FUNC_STATS_BASIC,
                        help='print out function stats (e.g. how many functions they pull in')
    parser.add_argument('--known-funcs-file', default=None,
                        help='a path to a file which contains a list of functions that are known and therefore are excluded ' +
                             'from off-target code generation')
    parser.add_argument('--lib-funcs-file', default=None,
                        help='experimental')
    parser.add_argument('--libc-includes', default=False,
                        help='Include libc headers in the generated files')
    parser.add_argument('--include-std-headers', nargs="+", default="",
                        help='a list of standard headers to include, e.g., stdbool.h')
    parser.add_argument('--include-asm', action='store_true',
                        help="Treat functions with assembly as internal")
    # the option below has the following meaning: let's assume we cut off functions at the module level
    # and some of the "first external" functions either don't pull in any others or pull in just a few functions
    # in these cases it might be better to include them in the off-target rather than to treat as external and
    # therefore introduce the necessity to implement stubs for them
    parser.add_argument('--external-inclusion-margin', type=int, default=0,
                        help='If a function treated as external recursively pulls in less than this number ' +
                             'of functions, treat this function and the functions pulled it as internal')
    parser.add_argument("--debug-bas", action='store_true',
                        help="If useds, BAS server address will not be modified with build/version/type string")
    parser.add_argument("--afl", type=str, choices=['none', 'stores', 'genl_ops'], default='none',
                        help="If used, generates AFL inits for stores/genl_ops")
    parser.add_argument("--init", action='store_true',
                        help="When used, initialization code will be generated")
    parser.add_argument("--dynamic-init", action="store_true",
                        help="When used, dynamic initialization code will be generated (this can be used along the '--init' option to improve the static initialization)")
    parser.add_argument("--kflat-img", default=OTGenerator.KFLAT_IMAGE_NAME,
                        help="The name of the KFLAT image file.")
    parser.add_argument("--used-types-only", action='store_true',
                        help="When used, only the used types will be generated - this affects stucts and enums")
    parser.add_argument("--dbjson2", action='store_true',
                        help="When used, we know that we operate on a second db.json created from off-target")
    parser.add_argument("--rdm-file", default=None,
                        help='BAS-generated JSON file with location->module map')
    parser.add_argument("--init-file", default=None,
                        help='JSON file with init data')
    parser.add_argument("--verify-struct-layout", action='store_true',
                        help=f"Add code to verify struct layout for generated struct types")
    parser.add_argument("--dump-global-hashes", action='store_true',
                        help=f"Dump hashes of globals to file {Engine.GLOBAL_HASH_FILE}")
    parser.add_argument("--debug-derefs", action='store_true',
                        help=f"Log debug messages from derefs parsing.")
    parser.add_argument("--stubs-for-klee", action="store_true",
                        help="When generating code for stubs returning pointers, add a special tag for KLEE")
    parser.add_argument("--always-inc-funcs-file", default=None,
                        help='a path to a file which contains a list of functions that should always be included ' +
                        'regardless of the chosen cut-off algorithm (provided they are encountered in the code)')
    parser.add_argument("--find-potential-targets", action="store_true",
                        help="Find potential targets for testing")
    parser.add_argument("--get-unique-names", default=None,
                        help="A file with a list of function names to be resolved uniquely.")
    parser.add_argument("--find-random-targets", default=0,
                        help="Find the given number of random functions and return the list of names")
    parser.add_argument("--dump-smart-init", action='store_true',
                        help="Dump the type cast information gathered during smart init.")
    parser.add_argument("--debug-analyze-types", action='store_true', default=False,
                        help=f"Analyze record types")
    parser.add_argument("--debug-vars-init", action='store_true', default=False,
                        help=f"Print debug info on vars init")
    parser.add_argument("--db-type", choices=['ftdb'], default='ftdb')
    parser.add_argument("--fptr-analysis", action="store_true",
                        help="When used, based on lightweight static analysis the code of possible functions that could be invoked through the function pointer calls are also added to the generated output")
    parser.add_argument("--dump-ids", action="store_true",
                        help="When used, dump ids of types functions and globals used in the OT code to a file named ids.json")
    parser.add_argument("--ignore-recursion-errors", action="store_true",
                        help="When the 'max recursion depth is reached, ignore that error and continue.")
    parser.add_argument("--single-init-only", action="store_true",
                        help="When the smart init mechanism finds more than one way to initialize, do not generate other options.")
    parser.add_argument("--unroll-macro-defs", action="store_true",
                        help="When generating function code unroll all expanded code that comes from macro invocations")
    parser.add_argument("--use-real-filenames", action="store_true",
                        help="When generating OT code use real file names rather than the file_<ID> scheme.")
    return parser


class ColorFormatter(logging.Formatter):
    # TODO: in the future we might consider putting
    # all logging setup in a separate module

    FORMAT = "%(asctime)-15s [AOT][%(levelname)s]: %(message)s (@ %(funcName)s %(filename)s:%(lineno)d)"

    def escape_sequence(type="reset"):
        color_map = {
            "reset": "0",
            logging.DEBUG: "0",
            logging.INFO: "0",
            logging.WARNING: "33",
            logging.ERROR: "31",
            logging.CRITICAL: "31;1",
        }
        return f"\x1b[{color_map[type]}m"

    def format(self, record):
        if sys.stdout.isatty():
            formatter = logging.Formatter(ColorFormatter.escape_sequence(record.levelno) + ColorFormatter.FORMAT + ColorFormatter.escape_sequence())
        else:
            formatter = logging.Formatter(ColorFormatter.FORMAT)
        return formatter.format(record)


def main():
    start_time = datetime.now()
    (fd, logname) = tempfile.mkstemp(dir=os.getcwd())
    logging.basicConfig(filename=logname, filemode="w",
                        level=logging.INFO, format=ColorFormatter.FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
    # https://stackoverflow.com/questions/13733552/logger-configuration-to-log-to-file-and-print-to-stdout
    streamlog = logging.StreamHandler(sys.stdout)
    streamlog.setFormatter(ColorFormatter())
    logging.getLogger().addHandler(streamlog)

    logging.info("We are happily running with the following parameters:")
    argvcopy = sys.argv[:]
    argvcopy[0] = os.path.abspath(argvcopy[0])
    logging.info("AOT_RUN_ARGS: |" + " ".join(argvcopy[:]) + "|")

    db_frontend = aotdb.connection_factory(aotdb.DbType.FTDB)

    parser = prepare_parser(db_frontend)
    args = parser.parse_args()
    
    retcode = 0
    try:
        engine = Engine()

        if False == engine.init(args, db_frontend):
            shutil.move(logname, f"{args.output_dir}/{Engine.LOGFILE}")
            sys.exit(1)

        logging.info(f"AOT_OUTPUT_DIR|{engine.out_dir}|")

        sys.setrecursionlimit(10000)

        funs = args.functions
        logging.info("Will generate off-target for functions {}".format(funs))
        engine.generate_off_target(args.functions, depth=10000)
    except Exception as e:
        # thanks to https://stackoverflow.com/questions/4564559/get-exception-description-and-stack-trace-which-caused-an-exception-all-as-a-st
        logger = logging.getLogger(__name__)
        logging.error("It's an exceptional execution")
        logger.exception(e)
        retcode = 1
    finally:

        engine.deinit()
        # move the config to the output dir
        if args.config:
            shutil.copy(args.config, engine.out_dir)

        if args.db:
            abspath = os.path.abspath(args.db)
            dbname = os.path.basename(args.db)
            os.symlink(abspath, f"{engine.out_dir}/{dbname}")
        args._get_args()
        end_time = datetime.now()
        logging.info(
            f"AOT_RUN_TIME_SECONDS: |{(end_time - start_time).total_seconds()}|")

        # move the log to the output dir
        shutil.move(logname, f"{args.output_dir}/{Engine.LOGFILE}")

        sys.exit(retcode)


if __name__ == "__main__":
    main()
