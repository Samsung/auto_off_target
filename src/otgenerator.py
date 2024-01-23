#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

#
# Off-target generator module
#

import logging
import os
import copy

class OTGenerator:

    AOT_HEADER = 'aot.h'
    AOT_HEADER_ID = -2

    AOT_STATIC_GLOBS_MARKER = '//AOT_STATIC_GLOBS_MARKER'
    AOT_STATIC_GLOBS_FPTRS = '//AOT_STATIC_GLOBS_FPTR_STUBS'

    KFLAT_IMAGE_NAME = "flat.img"

    def __init__(self, dbops, deps, codegen, cutoff, init, args):
        self.dbops = dbops
        self.deps = deps
        self.codegen = codegen
        self.cutoff = cutoff
        self.init = init
        self.args = args
        self.out_dir = args.output_dir
        # mapping original location of a header to the generated header
        self.location_to_header = {}
        self.header_to_location = {}

        self.static_inline_headers = {}

        # When dynamic initialization is used we have to initialize all global variables defined in the AoT to the values from kflat image
        #  To do that each definition of a global variable contains accompanying initialization function which does that
        #  The initialization function name is derived from the global variable hash
        #  The set below should contain all the derived names from global variable hashes defined in the AoT
        self.global_trigger_name_list = set()

        self.stats = {}
        self.all_types = set()
        self.all_funcs = set()

        self.fid_to_filename = {}
        self.funcs_init_data = {}
        self.globs_init_data = {}

        self.ot_funcs = set()

    # -------------------------------------------------------------------------

    def set_fid_to_filename(self, fid, filename):
        self.fid_to_filename[fid] = filename

    def _get_file_name_without_extenstion_from_fid(self, fid):
        full_path_to_source = self.dbops.srcidmap[fid]
        if full_path_to_source is None:
            return None
        source_file_name = os.path.basename(full_path_to_source)
        source_file_name_withot_extenstion = source_file_name[:source_file_name.rfind(".")]
        return source_file_name_withot_extenstion;

    # @belongs: otgenerator
    def _get_file_define(self, fid):
        filename = f"file_{fid}.c"
        define_str = filename.upper()
        define_str = define_str.replace(".", "_")
        define_str = define_str.replace("-", "_")

        return define_str

    # @entry_points: the list of functions that are called from main
    # NOTE: you can use the original "main" function if you specify it
    # as the only entry point
    # @belongs: otgenerator / codegen ?
    def _create_test_driver(self, entry_points, static_functions, all_global_ids):
        logging.info(
            "Creating test driver, entry_points {}".format(entry_points))
        # types = self._get_types_in_funcs(entry_points)

        str = self.codegen._get_file_header()
        str += "\n#include \"aot.h\"\n\n"
        # str += Generator.AOT_INCLUDE_MARKER
        str_header, str, name, func_ids, globals_id, types, internal_defs = self._create_src_file(-1, entry_points, all_global_ids, [], static_functions,
                                                                                                  stubs=False, test_driver=True)
        name = "aot.c"
        # types = set()
        # internal_defs = set()
        # types = self._get_types_in_funcs(entry_points, internal_defs, types_only=True)

        # str = self._get_file_header()

        # str += "\n#include \"aot.h\""
        # str += "\n#include \"aot_mem_init_lib.h\""
        str += "\n#include \"aot_fuzz_lib.h\""
        str += "\n#include \"aot_log.h\""
        str += "\n#include \"aot_recall.h\""

        if self.args.afl != 'none':
            str += "\n#include <stdio.h>"
        str += "\n#if defined AFL_PERSISTENT"
        str += "\n#include <unistd.h>"
        str += "\n#endif"

        if self.args.verify_struct_layout:
            str += "\n\n" + self.codegen._load_snippet("verify_layout_decl")

        str += "\n\n"
        # str_header = self._get_file_header()

        if self.args.afl == 'genl_ops':
            # inster genl_ops init snippet
            str += self.codegen._load_snippet("genl_ops_init")

        if self.args.init:
            str += "\n"
            str += "\t#if defined AFL_PERSISTENT && defined __AFL_HAVE_MANUAL_CONTROL\n"
            str += "\t__AFL_FUZZ_INIT()\n"
            str += "\t#endif\n"
            str += "\n"
            for id in self.fid_to_filename:
                if self.args.use_real_filenames:
                    source_file_name = self._get_file_name_without_extenstion_from_fid(id);
                    if source_file_name is None:
                        source_file_name = id
                    if not isinstance(source_file_name, int):                        
                        source_file_name = source_file_name.replace('-', '_')
                        source_file_name = source_file_name.replace('.', '_')
                        source_file_name = f"{source_file_name}_{id}"
                    str += f"void aot_init_globals_file_{source_file_name}(void);\n"
                else:
                    str += f"void aot_init_globals_file_{id}(void);\n"

        main_start = len(str)

        str += "\n\n/* ----------------------------- */\n" +\
            "/* Main test driver section      */\n" +\
            "/* ----------------------------- */\n" +\
            "int main(int AOT_argc, char* AOT_argv[]) {\n"

        if self.args.verify_struct_layout:
            str += self.codegen._load_snippet("verify_layout")
            str += "\n\n"

        str += "\taot_log_init();\n"


        if self.args.init:
            str += "\tinit_fuzzing(AOT_argc, AOT_argv);\n"
            str += "\t#if defined AFL_PERSISTENT && defined __AFL_HAVE_MANUAL_CONTROL\n"
            str += "\tunsigned char *fuzzbuff = __AFL_FUZZ_TESTCASE_BUF;\n"
            str += "\twhile (__AFL_LOOP(10000)) {\n"
            str += "\tint len = __AFL_FUZZ_TESTCASE_LEN;\n"
            str += "\tread_fuzzing_data_direct(fuzzbuff, len);\n"
            str += "\t#else\n"
            str += "\tread_fuzzing_data_file(AOT_argc, AOT_argv);\n"
            str += "\t#endif\n"
            str += "\tchar* tmpname = 0;\n"

        known_type_names = set()
        for t_id in types:
            t = self.dbops.typemap[t_id]
            if t["class"] == "record":
                known_type_names.add(t["str"])

        logging.info(f"known type names are {known_type_names}")
        new_types = set()

        if self.args.init:
            self.init._get_used_types_data()

            # since we're doing init it will be useful to get the data on all casts
            # of void* variables/members to other types
            # we can then try to generate more precise initialization code for void* members which
            # reflects their true type
            self.init._discover_casts(self.cutoff.internal_funcs)

            # str += "\n\t//Global vars init\n"
            # static_globals_noinit = set()
            # for g in all_globals:
            #     if g["hasinit"]:
            #         logging.info(
            #             f"Global {g['name']} already has an initializer -> skipping")
            #         continue
            #     elif g["linkage"] == "internal":
            #         # no init code for the global + the global is static
            #         logging.warning(
            #             f"Global {g['name']} lacks initializer, but it's static")
            #         static_globals_noinit.add(g["id"])
            #         continue
            #     pointers = []
            #     self.recursion_fuse = 0
            #     init_obj = None
            #     if function_id in self.funcs_init_data:
            #         init_data = self.funcs_init_data[function_id]
            #         param_tid, init_obj = init_data[i - 1]

            #     tmp_str, alloc = self._generate_var_init(
            #         g["name"], self.dbops.typemap[g["type"]], "", pointers, known_type_names=known_type_names, new_types=new_types,
            #         entity_name=g['name'], fuse=0)
            #     str += "\t" + tmp_str.replace("\n", "\n\t")

        globalsInit = False
        all_globals = []
        all_global_tids = []
        for g_id in all_global_ids:
            g = self.dbops.globalsidmap[g_id]
            all_globals.append(g)
            all_global_tids.append(g["type"])

        for f_id in entry_points:
            additional_tids = None
            if not globalsInit:
                # note: it's a hack - we will collect info on global derefs only on the first
                # function on the off-target functions list;
                # it should be fine most of the time: we usually generate only a single function target
                # besides, it's hard to do it other way as derefs are parsed in order and the order is
                # established by a call chain which depends on the entry point
                # TODO: establish an algorithm for selecting the best entry point for globals init
                additional_tids = all_global_tids

            if self.args.init:
                ret_val = self.init._parse_derefs_trace(
                    f_id, self.cutoff.internal_funcs, tids=additional_tids)
                self.funcs_init_data[f_id] = ret_val

            if self.args.init and not globalsInit:
                globalsInit = True  # globals are initialized on the first entry point

                self.globs_init_data = {}
                # the number of function args - data beyond args is for globals
                i = len(self.dbops.fnidmap[f_id]["types"]) - 1
                for g_id in all_global_ids:
                    self.globs_init_data[g_id] = self.funcs_init_data[f_id][i]
                    i += 1

                # initialize the globals
                # we'll skip those that have an initialzier or are static (as they cannot be pulled into another file)
                # Note: we may want to skip init if db.json will be generated from off-target; this is due to the fact
                # that the init code introduces references to sturcture members that may not be used otherwise in the code,
                # so we don't want to affect that in the db.json

                str += "\n\t//Global vars init\n"
                globals_noinit = set()
                for g in all_globals:
                    g_tid = g["type"]
                    g_t = self.dbops.typemap[g_tid]
                    g_t = self.dbops._get_typedef_dst(g_t)
                    if g["hasinit"]:
                        # if g_t["class"] != "const_array":
                        #     # enforcing init of all globals
                        #     pass
                        skip_init = True
                        # one more check: sometimes globals are pointers initialized to null

                        if g_t["class"] == "pointer":
                            initstr = g["init"]
                            if initstr == "((void *)0)":
                                if g['linkage'] == "internal":
                                    logging.info(
                                        f"Global {g['name']} has a null initialized and is static -> skipping for now")
                                    continue
                                logging.info(
                                    f"Global {g['name']} is a pointer initialized to null -> will generate init")
                                skip_init = False
                        if skip_init:
                            logging.info(
                                f"Global {g['name']} already has an initializer -> skipping")
                            continue
                    elif g["linkage"] == "internal":
                        # no init code for the global + the global is static
                        logging.warning(
                            f"Global {g['name']} lacks initializer, but it's static")
                        globals_noinit.add(g["id"])
                        continue
                    elif len(g_t["str"]) == 0:
                        logging.warning(
                           f"Global {g['name']} has anonymous type")
                        globals_noinit.add(g["id"]) 
                        continue

                    pointers = []
                    self.recursion_fuse = 0
                    init_obj = None
                    param_tid, init_obj = self.globs_init_data[g['id']]

                    tmp_str, alloc, brk = self.init._generate_var_init(
                        g["name"], self.dbops.typemap[g["type"]], pointers, known_type_names=known_type_names, new_types=new_types,
                        entity_name=g['name'], fuse=0, init_obj=init_obj)
                    str += "\t" + tmp_str.replace("\n", "\n\t")

                str += "\n"
                for id in self.fid_to_filename:
                    if self.args.use_real_filenames:
                        source_file_name = self._get_file_name_without_extenstion_from_fid(id)
                        if source_file_name is None:
                            source_file_name = id
                        if not isinstance(source_file_name, int):
                            source_file_name = source_file_name.replace('-', '_')
                            source_file_name = source_file_name.replace('.', '_')
                            source_file_name = f"{source_file_name}_{id}"
                        str += f"\taot_init_globals_file_{source_file_name}();\n"
                    else:  
                        str += f"\taot_init_globals_file_{id}();\n"

            if self.args.init:
                logging.info(f"init data for {f_id}: {ret_val}")
                for _t_id, _init_data in ret_val:
                    # logging.info(f"{_t_id} : {_init_data}")
                    obj = _init_data
                    self.init._debug_print_typeuse_obj(obj)

        if self.args.dynamic_init:
            if self.args.kflat_img:
                str += "\n\taot_kflat_init(\"%s\");\n" % self.args.kflat_img
            else:
                str += "\n\taot_kflat_init(\"%s\");\n" % OTGenerator.KFLAT_IMAGE_NAME

        if not self.args.no_main_function_calls:
            str += "\n\n\t".join([self.codegen._generate_function_call(x, static=(x in static_functions), known_type_names=known_type_names, new_types=new_types).replace("\n", "\n\t")
                                  for x in entry_points]) + "\n"

        if self.args.dynamic_init:
            str += "\taot_kflat_fini();\n\n"

        str += "\taot_GC();\n"
        str += "\t#if defined AFL_PERSISTENT && defined __AFL_HAVE_MANUAL_CONTROL\n"
        str += "\t}\n"
        str += "\t#endif\n"
        str += "    return 0;\n"
        str += " }\n"

        logging.info(f"We have the following new types: {new_types}")
        # internal_defs = set()
        additional_types, _ = self.deps._get_types_recursive(
            new_types, base_types=types, internal_defs=internal_defs)
        additional_types = self.deps._remove_duplicated_types(additional_types)
        self._filter_internal_types(additional_types, internal_defs)

        str_header += "\n// Additional types from casts\n"
        str_header += self.codegen._get_type_decls(additional_types)
        tmp_str, failed = self.codegen._get_type_defs(additional_types)
        for t_id in tmp_str:
            str_header += tmp_str[t_id]

        tmp = str[:main_start]
        for stub in self.init.fpointer_stubs:
            tmp += stub
        str = tmp + str[main_start:]

        if self.args.init:
            logging.info("We didn't initialize the following globals (static or anonymous type):")
            for g_id in globals_noinit:
                g = self.dbops.globalsidmap[g_id]
                logging.info(f"g['name']")
        for t_id in additional_types:
            types.append(t_id)

        return str_header, str, name, globals_id, types, internal_defs

    # -------------------------------------------------------------------------

    # @belongs: otgenerator?

    def _find_unique_filename(self, name, dir):
        path = f"{dir}/{name}"

        if not os.path.exists(path):
            return name

        i = 1
        while True:
            tmp_name = f"{i}_{name}"
            if not os.path.exists(f"{dir}/{tmp_name}"):
                return tmp_name
            i += 1

    # -------------------------------------------------------------------------

    # @belongs: otgenerator?
    def _get_header_guard(self, filename):
        guard = filename.replace(".", "_")
        guard = guard.replace("-", "_")
        guard = f"AOT_{guard}"
        guard = guard.upper()
        ifdefstr = f"#ifndef {guard}\n"
        ifdefstr += f"#define {guard}\n"
        return ifdefstr

    # -------------------------------------------------------------------------

    # @belongs: otgenerator?
    def _store_item_in_header(self, filename, contents):
        file_path = f"{self.out_dir}/{filename}"
        _str = ""
        if not os.path.isfile(file_path):
            _str += self._get_header_guard(filename) + "\n"
            if filename != OTGenerator.AOT_HEADER:
                _str += f"// Original location of this header: {self.header_to_location[filename]}\n"
            else:
                _str += "#include \"aot_replacements.h\"\n\n"
            _str += "#include \"aot_log.h\"\n\n"
            _str += "#include \"aot_mem_init_lib.h\"\n\n"

        _str += contents

        with open(f"{self.out_dir}/{filename}", "a+") as file:
            file.write(_str)

    # -------------------------------------------------------------------------

    # store an item in AoT-generated header file
    # item could be a function or a type
    # @belongs: otgenerator?
    def _map_item_to_header(self, item):
        filename = None
        if "location" in item:
            loc = item["location"].split(":")[0]
            if loc not in self.location_to_header:
                filename = loc.rsplit('/', 1)[-1]
                filename = self._find_unique_filename(filename, self.out_dir)
                self.location_to_header[loc] = filename
                self.header_to_location[filename] = loc
            else:
                filename = self.location_to_header[loc]

            logging.info(f"Using header file name {filename}")

        return filename

    # -------------------------------------------------------------------------

    # @belongs: otgenerator?
    def _create_static_inline_header(self, function):
        f_id = function["id"]

        filename = self._map_item_to_header(function)
        if filename is None:
            logging.error(
                f"Filename not found for function {function['name']}")
            raise Exception("Breaking execution due to error")
        self.static_inline_headers[f_id] = filename

        return filename

    # -------------------------------------------------------------------------

    # @belongs: otgenerator
    def _create_src_file(self, fid, functions, globs, includes, static_funcs, stubs=False, test_driver=False, create_header=False):

        internal_defs = set()
        if stubs is False:
            name = "file_{}.c".format(fid)
        else:
            name = "file_stub_{}.c".format(fid)

        if fid == OTGenerator.AOT_HEADER_ID:
            file_id = None
        else:
            file_id = fid

        logging.debug(
            "Getting types for functions {} in file {}".format(functions, name))

        global_type_decls = set()

        globals_ids = set()
        global_types = set()
        add_types = set()
        global_fwd_str = {}
        global_defs_str = {}
        additional_decls = set()
        additional_decls_fdecls = set()
        types = []
        failed_count = 0

        if stubs is False:
            # globals

            global_types, global_fwd_str, global_defs_str, globals_ids = self.deps._get_global_types(
                functions, globs, [], True, internal_defs, file_id, global_type_decls)

            types = self.deps._get_types_in_funcs(functions, internal_defs)
            logging.debug("File {} contains {} functions and {} types".format(
                name, len(functions), len(types)))

            containing_types = set()
            for t_id in global_types:
                if t_id in internal_defs:
                    logging.error(
                        f"type {t_id} is both inside global types and internal defs")
                    # let's get the containing type
                    if t_id not in self.deps.internal_types:
                        # check if we don't have a type duplicate
                        # what could have happened is that we have a duplicate types: e.g. one constant
                        # the other not, and only one of them has related containig type such as typedef
                        # in that case we need to find that typedef's id
                        dups = self.deps.dup_types[t_id]
                        found = False
                        for d in dups:
                            if d in self.deps.internal_types:
                                containing_types |= self.deps.internal_types[d]
                                found = True
                                # let's assume that the first dup in internal_types is
                                # sufficient
                                break
                        if found == False:
                            logging.error(
                                f"{t_id} not found in internal types")
                            raise Exception("Breaking execution due to error")
                    else:
                        containing_types |= self.deps.internal_types[t_id]
                    # make sure that the containing type is not an internal type of yet another type ...
                    tmp = containing_types
                    found = True
                    while found:
                        found = False
                        next = set()
                        for _t_id in tmp:
                            if _t_id in self.deps.internal_types:
                                next |= self.deps.internal_types[_t_id]
                                found = True
                        if found:
                            containing_types |= next
                            tmp = next

            if len(containing_types) > 0:
                internal_defs = set()
                logging.info(f"we have found {len(containing_types)}")
                tmp, _ = self.deps._get_types_recursive(
                    containing_types, [], internal_defs)
                tmp = self.deps._remove_duplicated_types(tmp)
                global_types, global_fwd_str, global_defs_str, globals_ids = self.deps._get_global_types(
                    functions, globs, tmp, True, internal_defs, file_id, global_type_decls)
                types = self.deps._get_types_in_funcs(functions, internal_defs)
                logging.debug("File {} contains {} functions and {} types".format(
                    name, len(functions), len(types)))
                global_types = tmp + global_types

        else:
            # generating stubs file - we only care about types from the declaration
            types = self.deps._get_types_in_funcs(
                functions, internal_defs, types_only=True)
            logging.debug("File {} contains {} functions and {} types".format(
                name, len(functions), len(types)))

        # remove duplicated types already coming from global types
        types_tmp = self.deps._remove_duplicated_types(types)
        types = self.deps._remove_duplicated_types_from(
            global_types, types_tmp)

        # generate code: types first, then functions
        failed_count = 0

        str = self.codegen._get_file_header(fid)
        str_header = self.codegen._get_file_header(fid)

        for h in self.args.include_std_headers:
            str_header += f"#include {h}\n"

        # before we include headers, lets introduce a define for this file
        # the define might be used in the header files
        str += f"#define {self._get_file_define(fid)}\n"

        if test_driver is False:
            str += "\n\n/* ----------------------------- */\n" +\
                "/* Includes section              */\n" +\
                "/* ----------------------------- */\n" +\
                "#include \"aot_log.h\"\n"

            # "#include <stdio.h>\n" +\
            # "#include <stdlib.h>\n" +\
            # "#include <string.h>"

        for i in includes:
            str += "#include " + i + "\n"

        # str += Generator.AOT_INCLUDE_MARKER + "\n"
        str += f"#include \"{OTGenerator.AOT_HEADER}\"\n"

        # check if we need to add the replacements include
        for f in functions:
            func = self.dbops.fnidmap[f]
            if func is not None:
                if "__replacement" in func["body"]:
                    str += "#include \"aot_replacements.h\"\n"

        if fid == OTGenerator.AOT_HEADER_ID:
            str_header += "\n\n// func decls which might be useful\n"
            str_header += "void* memset(void* dst, int ch, typeof(sizeof(int)) count);\n"
            str_header += "void* memcpy(void* dst, const void* src, typeof(sizeof(int)) n);\n"
            str_header += "void* malloc(typeof(sizeof(int)) size);\n"
            str_header += "int puts(const char* s);\n"
            str_header += "int strcmp(const char* a, const char* b);\n"

        logging.debug("name = {}, functions = {}, types = {}".format(
            name, functions, types))

        # generate code: types first, then functions
        inserted_funcs = set()
        if stubs is False:
            # in addition, we need to check all functions referenced in the file
            # as they might be defined in other file;
            # if we don't declare them in the best case we'll have a compiler
            # warning, but in the worst case we get a compile error, e.g. on constructs
            # like this: foo()->member (if foo returns a ptr to a struct)
            additional_decls = set()
            additional_decls_fdecls = set()
            functions_data = self.dbops.fnidmap.get_many(list(functions))
            if functions_data is not None:
                for func in functions_data:
                    if func["id"] not in self.cutoff.internal_funcs:
                        # since a function is not an internal function we
                        # don't need to further discover its refs
                        continue
                    if func["id"] in self.dbops.known_funcs_ids:
                        continue
                    if not self.args.include_asm and func["id"] in self.dbops.all_funcs_with_asm:
                        continue
                    funref_ids = func["funrefs"]
                    for call_id in funref_ids:
                        # we're only interested in functions as they are defined
                        # elsewhere
                        if call_id in self.dbops.fnidmap:
                            if call_id not in functions:
                                additional_decls.add(call_id)
                        elif call_id in self.dbops.fdmap:
                            if call_id not in functions:
                                additional_decls_fdecls.add(call_id)
                del functions_data

            # same applies to globals which are defined inside this file
            # this is because global initializers can contain function references
            globals_data = self.dbops.globalsidmap.get_many(list(globs))
            if globals_data is not None:
                for g in globals_data:
                    funref_ids = g["funrefs"]
                    for call_id in funref_ids:
                        # we're only interested in functions as they are defined
                        # elsewhere
                        if call_id in self.dbops.fnidmap:
                            if call_id not in functions:
                                additional_decls.add(call_id)
                        elif call_id in self.dbops.fdmap:
                            if call_id not in functions:
                                additional_decls_fdecls.add(call_id)
                del globals_data

            add_types = set()

            additional_decls_data = self.dbops.fnidmap.get_many(
                list(additional_decls))
            additional_decls_fdecls_data = self.dbops.fdmap.get_many(
                list(additional_decls_fdecls))

            #
            for func in additional_decls_data:
                for t in func["types"]:
                    type = self.dbops.typemap[t]
                    if type["class"] == "pointer":
                        dst_type = self.dbops.typemap[type["refs"][0]]
                        dst_class = dst_type["class"]
                        if dst_class == "record" or dst_class == "enum" or dst_class == "builtin":
                            continue
                    if t not in types:
                        add_types.add(t)
            for func in additional_decls_fdecls_data:
                for t in func["types"]:
                    type = self.dbops.typemap[t]
                    if type["class"] == "pointer":
                        dst_type = self.dbops.typemap[type["refs"][0]]
                        dst_class = dst_type["class"]
                        if dst_class == "record" or dst_class == "enum" or dst_class == "builtin":
                            continue
                    if t not in types:
                        add_types.add(t)

            if len(add_types) != 0:
                # we have some additional types to define; now we need to get their
                # dependencies
                add_types_rec, _ = self.deps._get_types_recursive(
                    add_types, list(types) + list(global_types), internal_defs)

                add_types_rec = self.deps._remove_duplicated_types(
                    add_types_rec)
                add_types = self.deps._remove_duplicated_types_from(
                    list(types) + list(global_types), add_types_rec)

            else:
                add_types = []
            del additional_decls_data
            del additional_decls_fdecls_data

            # let's unify all the types
            types += add_types
            types += global_types
            types, _ = self.deps._get_types_recursive(
                types, None, internal_defs)
            types = self.deps._remove_duplicated_types(types)

            # once we have all the types, we need to make sure that
            # some of them are not defined by others (in which case it makes sense
            # to generate the code only for the declaring outer type)
            # "internal_defs" set should store all the types defined inside other types
            self._filter_internal_types(types, internal_defs)

            if self.args.dynamic_init:
                str_header += "\n/* Dynamic init decls */\n"
                str_header += "#include \"dyn_init.h\"\n"

            str_header += "\n/* Type decls */\n"
            tmp = []
            tmp += types
            tmp += list(global_type_decls)
            if create_header:
                str_header += self.codegen._get_type_decls(tmp)

            globs_in_types = {}

            for t_id in types:  # global_types:
                t = self.dbops.typemap[t_id]
                if "globalrefs" in t:
                    globs_in_types[t_id] = set(t["globalrefs"])
                    globals_ids |= globs_in_types[t_id]

                decls = set()
                refs = set()
                self.deps._discover_type_decls_and_refs(t, decls, refs)
                # check if any of the internally defined types might have global references
                for subt_id in decls:
                    t = self.dbops.typemap[subt_id]
                    if "globalrefs" in t:
                        if t_id not in globs_in_types:
                            globs_in_types[t_id] = set(t["globalrefs"])
                        else:
                            globs_in_types[t_id] |= set(t["globalrefs"])
                        globals_ids |= globs_in_types[t_id]

            # before we can proceed with type generation we need to take functions into account
            # there are some type defs that include calls to functions (yeah!)
            # so we need to make sure that we put function declarations in the right place for these types
            types_copy = types[:]
            index = 0
            funcs_for_type = {}
            for t_id in types_copy:
                funcs_in_types = self.deps._get_funcs_from_types([t_id])

                # remove the functions we already inserted
                for f_id in inserted_funcs:
                    if f_id in funcs_in_types:
                        funcs_in_types.remove(f_id)

                if len(funcs_in_types) != 0:
                    logging.info(
                        f"for type {self.codegen._get_typename_from_type(self.dbops.typemap[t_id])} we found {len(funcs_in_types)} related functions")

                    f_types = self.deps._get_types_in_funcs(
                        funcs_in_types, internal_defs, types_only=True)
                    logging.info(f"The functions require {len(f_types)} types")

                    # let's now check which of the types were already defined so far
                    subrange = types[:index]

                    # we now need to insert the types right before the type that relies on functions
                    # note that we insert only the types which are not already defined so far
                    i = 0
                    for _t_id in f_types:
                        if _t_id not in subrange:
                            # remove the type which is likely defined afterwards
                            if _t_id in types:
                                types.remove(_t_id)
                            # re-insert it at the right place
                            types.insert(index + i, _t_id)
                            i += 1

                    # remember that we have to insert those function declarations
                    funcs_for_type[t_id] = funcs_in_types
                    inserted_funcs |= set(funcs_in_types)
                    index += i
                    # for _t_id in _types:
                    #    logging.info(f"type {self._get_typename_from_type(self.dbops.typemap[_t_id])}")
                    # sys.exit(1)
                index += 1

            # additional check: make sure that in case of name clashes we include all the clashing functions
            # just for the sake of completeness
            funcs_for_type_copy = copy.deepcopy(funcs_for_type)
            for t_id in funcs_for_type:
                for f_id in funcs_for_type[t_id]:
                    if f_id in self.deps.function_clashes:
                        funcs_for_type_copy[t_id] |= self.deps.function_clashes[f_id]
            funcs_for_type = funcs_for_type_copy
            types_str, failed = self.codegen._get_type_defs(
                types, funcs_for_type, fid, static_funcs)
            str_header += "\n/* Global type defs */\n"
            for t_id in types_str:

                if t_id in globs_in_types:
                    # this means that this specific global type referneces other globals
                    # we need to put these other globals fwd decl before that type
                    for gt_id in globs_in_types[t_id]:
                        str_header += "// fwd decl of a global used in the global type below\n"
                        if gt_id in global_fwd_str:
                            if create_header:
                                _str_header, ifgenerated = self.codegen._get_type_clash_ifdef(
                                    gt_id, fid)
                                str_header += _str_header
                                str_header += f"{global_fwd_str[gt_id]}\n"
                                str_header += self.codegen._get_type_clash_endif(
                                    gt_id, fid, ifgenerated)
                            del global_fwd_str[gt_id]
                        else:
                            g = self.dbops.globalsidmap[gt_id]
                            def_str = g["def"]
                            if create_header:
                                _str_header, ifgenerated = self.codegen._get_type_clash_ifdef(
                                    gt_id, fid)
                                str_header += _str_header
                                if not def_str.startswith("extern") and g["linkage"] == "external":
                                    # note: we check for the linkage as we might have come across
                                    # a static global
                                    str_header += "extern "
                                index = def_str.find("=")
                                if -1 != index:
                                    str_header += f"{def_str[:index]};\n"
                                else:
                                    str_header += f"{def_str};\n"
                                str_header += self.codegen._get_type_clash_endif(
                                    gt_id, fid, ifgenerated)
                _str_header, ifgenerated = self.codegen._get_type_clash_ifdef(
                    t_id, fid)
                str_header += _str_header
                str_header += types_str[t_id]
                str_header += self.codegen._get_type_clash_endif(
                    t_id, fid, ifgenerated)
            failed_count += failed

        globals_defs = "\n\n// Global vars definitions\n\n"
        globs_with_typedef = []
        # globals forward
        str_header += "\n/* Forward decls of global vars */\n"
        for g_id in global_fwd_str:
            g = self.dbops.globalsidmap[g_id]
            if "decls" in g:
                skip = False

                decl_tids, real_tid = self.dbops._get_global_decl_types(
                    g["decls"], g["refs"], g["type"])

                if real_tid in decl_tids:
                    skip = True
                    if g_id in global_defs_str:  # that's true only if global is defined in this file
                        globals_defs += f"{global_defs_str[g_id]}\n"
                        globs_with_typedef.append(g_id)
                        del global_defs_str[g_id]

                if skip:
                    continue
            if create_header and g_id in global_fwd_str:
                str_header += self.codegen._get_global_clash_ifdef(g_id, fid)

                if fid == OTGenerator.AOT_HEADER_ID and g["linkage"] != "internal" and not global_fwd_str[g_id].startswith("extern"):
                    prefix = "extern "
                else:
                    prefix = ""
                str_header += "{}{}\n".format(prefix, global_fwd_str[g_id])
                str_header += self.codegen._get_global_clash_endif(g_id, fid)

        # print function declarations
        if create_header:
            str_header += "\n\n#include \"aot_lib.h\"\n\n"
            str_header += "\n\n/* ----------------------------- */\n" +\
                "/* Function declarations section */\n" +\
                "/* ----------------------------- */\n\n"

            str_header += "\n/*Functions defined in this file*/\n"

            # do not declare functions which were declared along the types
            functions_copy = [
                f_id for f_id in functions if f_id not in inserted_funcs]
            additional_decls_copy = [
                f_id for f_id in additional_decls if f_id not in inserted_funcs]
            additional_decls_fdecls_copy = [
                f_id for f_id in additional_decls_fdecls if f_id not in inserted_funcs]

            str_header += self.codegen._get_func_decls(
                fid, functions_copy, static_funcs)
            str_header += "\n/* Additional function decls */\n"
            str_header += self.codegen._get_func_decls(fid,
                                                       additional_decls_copy, section_header=False)
            str_header += self.codegen._get_func_decls(fid,
                                                       additional_decls_fdecls_copy, section_header=False)

        if test_driver is False:
            # print globals
            str += "\n\n/* ----------------------------- */\n" +\
                "/* Globals definition section    */\n" +\
                "/* ----------------------------- */\n\n"
            # const globals go first as they might be used in the initializers
            ids = list(global_defs_str.keys())
            for g_id in ids:
                g = self.dbops.globalsidmap[g_id]
                if g["def"].startswith("const ") or g["def"].startswith("static const "):
                    globals_defs += f"{global_defs_str[g_id]}\n"
                    self.global_trigger_name_list.add("%s" % (g["hash"].replace(
                        "/", "__").replace(".", "____").replace("-", "___")))
                    del global_defs_str[g_id]

            for g_id in global_defs_str:
                g = self.dbops.globalsidmap[g_id]
                globals_defs += f"{global_defs_str[g_id]}\n"
                self.global_trigger_name_list.add("%s" % (g["hash"].replace(
                    "/", "__").replace(".", "____").replace("-", "___")))

            for g_id in globs_with_typedef:
                g = self.dbops.globalsidmap[g_id]
                self.global_trigger_name_list.add("%s" % (g["hash"].replace(
                    "/", "__").replace(".", "____").replace("-", "___")))


            str += globals_defs

        if stubs == False:
            str_header += "\n/*Static inline headers*/\n"
            functions_copy = functions.copy()
            for f_id in functions_copy:
                if f_id in self.static_inline_headers:
                    if create_header and f_id not in self.dbops.known_funcs_ids:
                        str_header += self.codegen._get_func_defs(fid,
                                                                  [f_id], section_header=False)
                    functions.remove(f_id)

        if test_driver is False:

            # print function definitions
            str += "\n\n/* ----------------------------- */\n" +\
                "/* Function definitions section  */\n" +\
                "/* ----------------------------- */\n"
            str += self.codegen._get_func_defs(fid,
                                               functions, stubs=stubs, file=name)

            # generate static functions wrappers
            if len(static_funcs) != 0:
                str += "\n\n/* ----------------------------- */\n" +\
                    "/* Static function wrappers      */\n" +\
                    "/* ----------------------------- */\n"
                for f in static_funcs:
                    function = self.dbops.fnidmap[f]
                    fname = function["name"]
                    wrapper_name = "wrapper_{}_{}".format(fname, f)
                    decl = function["declbody"].replace(
                        "{}(".format(fname), "{}(".format(wrapper_name))
                    decl = decl.replace("static ", "")
                    decl = decl.replace("inline ", "")
                    str += "{} ".format(decl)
                    str += "{\n"
                    str += "\treturn {}(".format(fname)
                    params = ""
                    params_locals = []
                    for l in function["locals"]:
                        if l["parm"] == True:
                            params_locals.append(l)
                    params_locals.sort(key=lambda k: k["id"])
                    for l in params_locals:
                        if len(params) == 0:
                            params = l["name"]
                        else:
                            params = params + ", {}".format(l["name"])

                    str += "{});\n".format(params)
                    str += "\n}\n"

            if 0 != failed_count:
                logging.warning("Code generation failed for " +
                                str(failed_count) + " types")
            types_cnt = len(types) + len(add_types) + len(global_types)
            f_cnt = len(functions)
            self.stats[name] = {}
            self.stats[name]["types"] = types_cnt
            self.stats[name]["funcs"] = f_cnt

            logging.info("File {} : {} types and {} functions {} globals".format(
                name, types_cnt, f_cnt, len(globs)))

        if test_driver is False and stubs is False:
            str += "\n /* Static globals init */\n"
            str += f"\n{OTGenerator.AOT_STATIC_GLOBS_FPTRS}\n"
            if self.args.use_real_filenames:
                source_file_name = self._get_file_name_without_extenstion_from_fid(fid)
                if source_file_name is None:
                    source_file_name = fid
                if not isinstance(source_file_name, int):
                    source_file_name = source_file_name.replace('-', '_')
                    source_file_name = source_file_name.replace('.', '_')
                    source_file_name = f"{source_file_name}_{fid}"
                str += f"void aot_init_globals_file_{source_file_name}(void) {{\n"
            else:
                str += f"void aot_init_globals_file_{fid}(void) {{\n"
            str += f"\tchar* tmpname;\n"
            str += f"\n{OTGenerator.AOT_STATIC_GLOBS_MARKER}\n"
            str += "}\n"

        ret_types = set()
        ret_types |= set(types)
        ret_types |= set(add_types)
        ret_types |= set(global_types)

        self.all_types |= ret_types
        self.all_funcs |= set(functions)
        self.all_funcs |= set(additional_decls)
        self.all_funcs |= set(additional_decls_fdecls)

        ret_funcs = set()
        ret_funcs |= set(functions)
        ret_funcs |= set(additional_decls)
        ret_funcs |= set(additional_decls_fdecls)

        return str_header, str, name, ret_funcs, globals_ids, list(ret_types), internal_defs

    # --------------------------------------------------------------------------

    # @belongs: otgenerator or codegen
    def adjust_funcs_lib(self):
        if 0 == len(self.dbops.lib_funcs):
            return True

        contents = ""
        with open(f"{self.out_dir}/aot_lib.h", "r") as f:
            contents = f.readlines()
        with open(f"{self.out_dir}/aot_lib.h", "w") as f:
            f.write(self._get_header_guard("aot_lib.h"))
            f.write(
                "\n// Enable user-defined library functions specified in lib-funcs-file\n\n")
            for func_name in self.dbops.lib_funcs:
                if func_name in self.deps.known_funcs_present:
                    f.write(f"#define AOT_{func_name.upper()}\n")
            f.writelines(contents)
            f.write("\n#endif")

    # -------------------------------------------------------------------------

    # @belongs: deps?
    def _filter_internal_types(self, types, internal_defs):
        for t in internal_defs:
            to_check = []
            if t in self.deps.dup_types:
                # dup_types[t] contains t too
                to_check = self.deps.dup_types[t]
            else:
                to_check.append(t)

            to_remove = []
            for t_id in types:
                if t_id in to_check:
                    to_remove.append(t_id)
            for t_id in to_remove:
                types.remove(t_id)
                logging.info(
                    "Removing type {} as it's defined inside another emitted type".format(t_id))

        # filter out implicit types:
        for tid in self.deps.implicit_types:
            if tid in types:
                types.remove(tid)

    # --------------------------------------------------------------------------

    def _generate_static_inline_headers(self, funcs):
        # before we generate all source files, let's generate headers containing
        # static inline functions
        for f_id in funcs:
            f = self.dbops.fnidmap[f_id]

            if f is not None and "inline" in f and f["inline"]:
                filename = self._create_static_inline_header(f)
                logging.info(f"Created static / inline header {filename}")
