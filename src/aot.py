#!/usr/bin/env python3

# Auto off-target PoC
###
# Based on sec-tools/misc/fuzzwrap by b.zator@samsung.com
# Developed by    t.kuchta@samsung.com
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

from readline import get_current_history_length
from toposort import toposort, toposort_flatten, CircularDependencyError
import subprocess
import functools
import shutil
import psutil
import difflib
import json
import itertools
import traceback
import logging
import random
import tempfile
import copy
import argparse
import sys
import os
import re
import time
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import depth_first_order
import numpy as np
import struct 
import collections
from datetime import datetime

from BASconnector import BASconnector
import aotdb
class Module:

    def __init__(self, path, isbase=False):
        self.fids = set()
        self.path = path
        self.depth = path.count("/")
        self.isbase = isbase


class File:

    def __init__(self):
        self.funcs = []
        self.globals = []
        self.types = []
        self.filename = ""


class TypeUse:

    instance_id = 0
    def __init__(self, t_id, original_tid, is_pointer):
        self.id = TypeUse.instance_id
        TypeUse.instance_id += 1
        self.t_id = t_id # the last known type of this object
        self.original_tid = original_tid
        self.is_pointer = is_pointer
        self.name = ""
        self.cast_types = [] # a list of all known types for this object
        self.offsetof_types = [] # a list of tuples (containig type TypeUse, member number)
        # a reverse relationship to the types that were used in the offsetof
        # operator to retrieve this type
        self.contained_types = [] # a list of tuples (member number, TypeUse object)
                                  # note: this list has a precedence over used_members when it
                                  # comes to init
        self.used_members = {} # for a given type, maps used member of that type 
                               # to the related TypeUse objects

    def __str__(self):
        return f"[TypeUse] id = {self.id} t_id = {self.t_id} original_tid = {self.original_tid} " +\
            f"is_pointer = {self.is_pointer} name = '{self.name}' offsetof_types = {self.offsetof_types} " +\
            f"contained_types = {self.contained_types} used_members = {self.used_members} cast_types = {self.cast_types}"

    def __repr__(self):
        return f"[TypeUse id={self.id} t_id={self.t_id} original_tid={self.original_tid}]"

class Generator:
    LOGFILE = "aot.log"

    # function stats details
    FUNC_STATS_NONE = 'none'
    FUNC_STATS_BASIC = 'basic'
    FUNC_STATS_DETAILED = 'detailed'

    # cut-off algorithm
    CUT_OFF_NONE = 'none'
    CUT_OFF_FUNCTIONS = 'functions'
    CUT_OFF_MODULE = 'module'
    CUT_OFF_DIRS = 'dirs'
    CUT_OFF_FILES = 'files'
    CUT_OFF_NAMED_MODULES = 'named_modules'  # currently unsupported

    DEFAULT_OUTPUT_DIR = 'off-target'

    CAST_PTR_NO_MEMBER = -1

    AOT_INCLUDE_MARKER = 'AOT_INCLUDE_MARKER'
    AOT_HEADER = 'aot.h'
    AOT_HEADER_ID = -2

    AOT_STATIC_GLOBS_MARKER = '//AOT_STATIC_GLOBS_MARKER'
    AOT_STATIC_GLOBS_FPTRS = '//AOT_STATIC_GLOBS_FPTR_STUBS'
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

    GLOBAL_HASH_FILE = 'global.hashes' 

    AOT_LITERALS_FILE = 'aot_literals'
    INT_LITERAL = 'integer'
    FLOAT_LITERAL = 'floating'
    CHAR_LITERAL = 'character'
    STRING_LITERAL = 'string'
    MAX_STRING_LITERAL_LEN = 16

    VERIFY_STRUCT_LAYOUT_TEMPLATE = "vlayout.c.template"
    VERIFY_STRUCT_LAYOUT_SOURCE = "vlayout.c"
    VERIFY_STRUCT_TYPE_LAYOUT_BLACKLIST = set(["__builtin_va_list","va_list"])

    FUNCTION_POINTER_STUB_FILE_TEMPLATE = "fptr_stub.c.template"
    FUNCTION_POINTER_STUB_FILE_SOURCE = "fptr_stub.c"
    FUNCTION_POINTER_KNOWN_FUNCS_STUB_FILE_TEMPLATE = "fptr_stub_known_funcs.c.template"
    FUNCTION_POINTER_KNOWN_FUNCS_STUB_FILE_SOURCE = "fptr_stub_known_funcs.c"

    KFLAT_IMAGE_NAME = "flat.img"

    VERIFY_STRUCT_TEMPLATE = """    VERIFY_STRUCT(%s,%d,
%s
    );
"""

    VERIFY_UNION_TEMPLATE = """    VERIFY_UNION(%s,%d,
%s
    );
"""

    VERIFY_STRUCT_TYPE_TEMPLATE = """    VERIFY_STRUCT_TYPE(%s,%d,
%s
    );
"""

    ## {0} - global variable trigger name
    ## {1} - address specifier ('&' or '' in case of global variable array type)
    ## {2} - global variable name
    ## {3} - trigger name
    DYNAMIC_INIT_GLOBAL_VARIABLE_TEMPLATE = """void init_{3}() {{
  unsigned long target_size;
  void* ptr = aot_kflat_root_by_name("{0}", &target_size);
  if(ptr)
    memcpy({1}{2} ,ptr, target_size);
  else
    puts("[Unflatten] Failed to load global {0}");
}}"""

    ## {0} - function variable name
    ## {1} - function trigger basename
    ## {2} - extended root pointer name
    ## {3} - function variable type in text form
    DYNAMIC_INIT_FUNCTION_VARIABLE_TEMPLATE = """
    /* Dynamically initialize variable '{0}' using kflat */
    void* {1}_{0}_ptr = aot_kflat_root_by_name("{2}", (void*) 0);
    if({1}_{0}_ptr)
      {0} = ({3}) {1}_{0}_ptr;
    else
      puts("[Unflatten] Failed to load local variable {2}");
"""

    # this is a special value returned by function stubs returning a pointer
    # it's supposed to be easily recognizable (407 == AOT)
    # the value needs to be in sync with what we set in fuzz_lib
    AOT_SPECIAL_PTR = 0x40710000 
    AOT_SPECIAL_PTR_SEPARATOR = 0x1000

    MAX_RECURSION_DEPTH=50

    def __init__(self, logname):
        self.FOPS_FILE = "fops.json"
        self.DBJSON_FILE = "db.json"
        self.db = None
        self.genclass = {"record", "record_forward", "enum", "enum_forward"}
        self.functions = set()
        self._visited_calls = set()
        self.out_dir = Generator.DEFAULT_OUTPUT_DIR
        self.defined_globals = set()
        self.random_names = set()
        self.deps_cache = {}
        self.stats = {}
        self.all_types = set()
        self.all_funcs = set()
        self.dup_types = {}
        self.internal_types = {}
        self.bassconnector = None
        self.modules = {}  # map modules -> functions
        self.fid_to_mods = {}  # map functions -> modules
        self.fid_to_dirs = {}  # map functions -> source directories
        self.global_types = set()
        self.implicit_types = set()
        self.identical_typedefs = {}
        # cache to limit the number of expensive recursive queries
        self.stats_cache = {}

        # known functions are those that will be provided by the target system/env
        # e.g. printf
        self.known_funcs_data = {}
        self.known_funcs_ids = set()
        self.known_funcs_present = set()
        self.lib_funcs_ids = set()

        # builtin functions
        self.builtin_funcs_ids = set()

        self.always_inc_funcs_ids = set()

        self.static_funcs_map = {}

        # the set of functions that we wish to emit the code for
        self.internal_funcs = set()

        # the set of a "front" of external functions, i.e. first functions that are outside
        # of what is considered to be an off-target border
        self.external_funcs = set()

        # the set of functions with inline assembly
        self.funcs_with_asm = {}

        # all the functions with inline assembly in the database
        self.all_funcs_with_asm = set()

        self.generated_functions = 0
        self.generated_stubs = 0

        self.ptr_init_size = 1  # when initializing pointers use this a the number of objects
        self.array_init_max_size = 32 # when initializing arrays use this a an upper limimit
        # to create
        self.fpointer_stubs = []
        self.void_pointers = {}
        self.casted_pointers = {}
        self.casted_pointers2 = {}
        self.offset_pointers = {}
        self.funcs_init_data = {}

        # mapping original location of a header to the generated header
        self.location_to_header = {}
        self.header_to_location = {}
        self.sources_to_types = {}
        self.file_contents = {}

        self.clash_type_to_file = {}
        self.clash_global_to_file = {}
        self.clash_function_to_file = {}

        self.stub_to_return_ptr = {}
        self.stubs_with_asm = set()
        self.trace_cache = {}

        self.globs_init_data = {}
        self.fid_to_filename = {}
        self.casted_types = set()

        self.literals = {}

        self.type_clash_nums = {}
        self.type_clash_counter = 0
        self.glob_clash_nums = {}
        self.glob_clash_counter = 0
        self.func_clash_nums = {}
        self.func_clash_counter = 0


        self.logname = logname
        self.tagged_vars_count = 0

        self.member_usage_info = {}

    # -------------------------------------------------------------------------

    def init(self, args, db_frontend):
        self.out_dir = args.output_dir
        self.out_dir_abs = os.path.abspath(self.out_dir)
        self.afl = args.afl

        predefined_files = ["aot_replacements.h", "Makefile", "aot_lib.h", "aot_lib.c", "aot_mem_init_lib.h",
                            "aot_mem_init_lib.c", "aot_fuzz_lib.h", "aot_fuzz_lib.c", "aot_log.h", "aot_log.c",
                            "build.sh",  
                            "vlayout.c.template", "dfsan_ignore_list.txt", 
                            "aot_recall.h", "aot_recall.c", "aot_dfsan.c.lib"]
        
        # create output directory
        if os.path.exists(self.out_dir):
            msg = f"The output directory {self.out_dir} already exists!"
            logging.error(msg)
            with open(self.out_dir + "/" + "out_dir_error.txt", "w") as file:
                file.write(msg)
            return False

        os.makedirs(self.out_dir)
        
        # copy the predefined files
        for f in predefined_files:
            # https://www.blog.pythonlibrary.org/2013/10/29/python-101-how-to-find-the-path-of-a-running-script/
            shutil.copyfile(
                f"{os.path.abspath(os.path.dirname(sys.argv[0]))}/resources/{f}", f"{self.out_dir}/{f}")
            shutil.copymode(
                f"{os.path.abspath(os.path.dirname(sys.argv[0]))}/resources/{f}", f"{self.out_dir}/{f}")

        if False == self._sanity_check(args):
            logging.error("Sanity check failed in he Generator object")
            return False

        # 1) DB connection
        self.db = db_frontend.establish_db_connection(args)
        self.db_frontend = db_frontend

        self.version = f"{args.product}_{args.version}_{args.build_type}"
        self.cut_off = args.cut_off
        self.co_funcs = set(args.co_funcs)
        self.co_dirs = set(args.co_dirs)
        self.co_modules = set(args.co_modules)
        self.co_files = set(args.co_files)
        self.func_stats = args.func_stats
        self.known_funcs_file = args.known_funcs_file
        self.lib_funcs_file = args.lib_funcs_file
        self.always_inc_funcs_file = args.always_inc_funcs_file
        self.lib_funcs = []
        self.libc_includes = args.libc_includes
        self.include_std_headers = args.include_std_headers
        self.include_asm = args.include_asm

        self.external_inclusion_margin = args.external_inclusion_margin

        self.init = args.init
        self.dump_smart_init = args.dump_smart_init
        self.dynamic_init = args.dynamic_init
        self.kflat_img = args.kflat_img

        self.used_types_only = args.used_types_only
        self.dbjson2 = args.dbjson2
        self.import_json = args.import_json
        self.rdm_file = args.rdm_file
        self.init_data = None
        self.init_file = args.init_file
        self.source_root = args.source_root
        self.verify_struct_layout = args.verify_struct_layout
        self.struct_types = []
        self._debug_derefs = args.debug_derefs
        self.stubs_for_klee = args.stubs_for_klee
        self.fptr_analysis = args.fptr_analysis

        self.dump_global_hashes = args.dump_global_hashes
        self.global_hashes = []
        
        ## For each non-inline function generated in the AoT there is a mapping that maps
        #   the function symbol into its address (fptr_stub.c file).
        #  In case of static functions the only way to get its address is to initialize global
        #   function pointer with the function address in the containing translation unit
        #  For example assuming that we have 'static int myfun(void)' function that originated from 'kernel/mm/myfile.c'
        #   we would have the following function pointer stub:
        #   'int (*__pf__kernel__mm__myfile____c__myfun)(void) = myfun;'
        #  Then using the '__pf__kernel__mm__myfile____c__myfun' symbol as a 'const char*'
        #   we can acquire the 'myfun' address in the AoT
        #  The set below should contain all the symbol names along with function id for all non-inline functions available in the AoT
        self.function_pointer_stubs = set()
        
        # The same as above but for the library functions available in the 'aot_lib.c' file used in the AoT
        self.lib_function_pointer_stubs = set()
        
        ## When dynamic initialization is used we have to initialize all global variables defined in the AoT to the values from kflat image
        #  To do that each definition of a global variable contains accompanying initialization function which does that
        #  The initialization function name is derived from the global variable hash
        #  The set below should contain all the derived names from global variable hashes defined in the AoT
        self.global_trigger_name_list = set()
        
        ## For some global variables only declaration is included ('extern') in the 'aot.h' file.
        #  The set below should contain all the derived names from global variable declarations
        self.global_trigger_name_list_exclude = set()

        self.literals[Generator.INT_LITERAL] = set()
        self.literals[Generator.FLOAT_LITERAL] = set()
        self.literals[Generator.CHAR_LITERAL] = set()
        self.literals[Generator.STRING_LITERAL] = set()

        self.create_indices()
        self.discover_type_duplicates()
        self.discover_internal_types()
        basserver = "localhost"
        if args.config:
            with open(args.config, "r") as c:

                logging.info(f"AOT_CONFIG:|{args.config}|")

                cfg = json.load(c)
                if "BASserver" not in cfg:
                    logging.error("Cannot find BASserver in the config file.")
                    return False
                    # return True

                basserver = cfg["BASserver"]
        if not args.debug_bas:
            self.bassconnector = BASconnector(basserver,
                                                args.product, args.version, args.build_type, db=self.db)
        else:
            self.bassconnector = BASconnector(basserver, db=self.db)


        if self.rdm_file is not None:
            self.bassconnector.import_data_to_db(self.rdm_file)

        if args.find_potential_targets:
            # we will look for a potential testing targets
            self._find_potential_targets()
            return False

        if args.get_unique_names:
            # let's find a non-unique function names
            self._get_unique_names(args.get_unique_names)
            return False

        if int(args.find_random_targets) != 0:
            self._find_random_targets(int(args.find_random_targets))
            return False

        if args.debug_analyze_types:
            # analyze all types
            self._analyze_types()
            return False

        self.debug_vars_init = args.debug_vars_init

        # Get the list of possible functions assigned to function pointers
        if self.fptr_analysis:
            self.fpointers = self._infer_functions()
        return True

        # 2) db.json file
        # self.db = ctypelib.ModuleTypeGraph("db.json",False)
        # return True

    # -------------------------------------------------------------------------

    def deinit(self):
        self.db_frontend.close_db_connection()

    # -------------------------------------------------------------------------

    # Analyzes function invocations through a pointer and tries to assign
    #  a list of possible functions that could be invoked through that pointer
    # Returns the following map:
    #  {
    #    function_id : (expr,[called_fun_id,...])
    #  }
    # where,
    #  function_id: a function where the function invocation through a pointer takes place
    #  expr: the expression of the function invocation through a pointer
    #  called_fun_id: function id that could be possible stored (and invoked) through the pointer at the given expression
    def _infer_functions(self):

        # save all funcs
        funcsaddresstaken = set()
        funcsbytype = {}
        funcTypeCandidates = {}

        for fun in self.db.db["funcs"]:
            for deref in fun["derefs"]:
                if deref["kind"] != "assign" and deref["kind"] != "init":
                    continue
                functions = list(filter(lambda x: x["kind"] == "function", deref["offsetrefs"]))
                if not functions:
                    continue
                for function in functions:
                    funcsaddresstaken.add(function["id"])

        # from global variables take all funrefs as funcs with address taken
        for var in self.db.db["globals"]:
            for funid in var["funrefs"]:
                funcsaddresstaken.add(funid)

        funDict = {}
        for fun in self.db.db["funcs"]:
            funDict[fun["id"]] = fun

        for function in funcsaddresstaken:
            if function not in funDict:  # handle if it is in funcdecls or unresolved
                continue
            f = funDict[function]
            typeTuple = tuple(f["types"])
            if typeTuple not in funcsbytype:
                funcsbytype[typeTuple] = [f]
            else:
                funcsbytype[typeTuple].append(f)

        for typ in self.db.db["types"]:
            if typ["class"] == "function":
                typeTuple = tuple(typ["refs"])
                if typeTuple in funcsbytype:
                    funcTypeCandidates[typ["id"]] = funcsbytype[typeTuple]
                else:
                    funcTypeCandidates[typ["id"]] = []

        globalDict = {}
        for glob in self.db.db["globals"]:
            globalDict[glob["id"]] = glob

        typeDict = {}
        for fun in self.db.db["types"]:
            typeDict[fun["id"]] = fun

        # first level struct assignment
        fucnsFirstLevelStruct = set()
        for fun in self.db.db["funcs"]:
            for deref in fun["derefs"]:
                if deref["kind"] != "assign" and deref["kind"] != "init":
                    continue
                functions = list(filter(lambda x: x["kind"] == "function", deref["offsetrefs"]))
                if not functions:
                    continue
                if deref["offsetrefs"][0]["kind"] != "member":
                    continue
                structDerefId = deref["offsetrefs"][0]["id"]
                structTypeId = fun["derefs"][structDerefId]["type"][-1]
                structMemberId = fun["derefs"][structDerefId]["member"][-1]

                for function in functions:
                    fucnsFirstLevelStruct.add((structTypeId, structMemberId, function["id"]))

        # seems that we need to add also those from fops
        recordsByName = {}
        for type in self.db.db["types"]:
            if type["class"] != "record":
                continue
            recordsByName.setdefault(type["str"], [])
            recordsByName[type["str"]].append(type)

        fopbased = set()

        for fop in self.db.db["fops"]["vars"]:
            for record in recordsByName[fop["type"]]:
                for member in fop["members"]:
                    fucnsFirstLevelStruct.add((record["id"], int(member), fop["members"][member]))
                    fopbased.add((record["id"], member, fop["members"][member]))

        funcsbytypeFirstLevel = {}

        for structId, memberId, functionId in fucnsFirstLevelStruct:
            if functionId not in funDict:  # handle if it is in funcdecls or unresolved
                continue
            f = funDict[functionId]
            # typeTuple = tuple(f["types"])   we dont need type.... i think
            funcsbytypeFirstLevel.setdefault((structId, memberId), [])
            funcsbytypeFirstLevel[(structId, memberId)].append((f))

        firstError = True

        # and than we need to get icalls with struct type
        iCallsStruct = []
        for func in self.db.db["funcs"]:
            for deref in func["derefs"]:
                if deref["kind"] != "member":
                    continue
                if not "mcall" in deref:
                    continue
                for i, membcall in enumerate(deref["mcall"]):
                    if membcall == -1:
                        continue
                    structType = typeDict[deref["type"][i]]
                    while structType["class"] == "pointer" or structType["class"] == "typedef":
                        structType = typeDict[structType["refs"][0]]

                    if  deref["member"][i] >= len(structType["refs"]):
                        continue

                    functype = typeDict[structType["refs"][deref["member"][i]]]
                    memberId = deref["member"][i]
                    while functype["class"] == "pointer" or functype["class"] == "typedef" or functype["class"] == "const_array":
                        functype = typeDict[functype["refs"][0]]
                    if functype["class"] == "function":
                        iCallsStruct.append(((structType["id"], memberId), deref, func, tuple(functype["refs"])))
                    elif functype["str"] == "void":
                        iCallsStruct.append(((structType["id"], memberId), deref, func, None))
                    else:
                        logging.error(f"Unsupported case found!", same_line=True)
                        logging.error(f"Unsupported case found!", same_line=True)
                        logging.error(f">>> functype: {functype}")
                        logging.error(f">>> func: {func['name']}")
                        logging.error(f">>> deref: {deref}")
                        logging.error("Tracing function pointer calls", new_line=False)
                        continue

        output = {}
        for firstLevelId, deref, func, functypetuple in iCallsStruct:
            funcCandidates = []
            if firstLevelId in funcsbytypeFirstLevel:
                funcCandidates = [{"id": x["id"]} for x in funcsbytypeFirstLevel[firstLevelId]]
            elif functypetuple is not None and functypetuple in funcsbytype:
                funcCandidates = [{"id": x["id"]} for x in funcsbytype[functypetuple]]
            output.setdefault(func["id"], {})
            output[func["id"]][deref["expr"]] = funcCandidates

        funccals = []
        for fun in self.db.db["funcs"]:
            for deref in fun["derefs"]:
                if deref["kind"] == "function":
                    funccals.append((deref, fun))
        iCallsVar = []
        for deref, fun in funccals:
            if deref["offsetrefs"][0]["kind"] == "unary":
                #deref = fun["derefs"][deref["offsetrefs"][0]["id"]]
                continue

            if deref["offsetrefs"][0]["kind"] == "global":
                typeId = globalDict[deref["offsetrefs"][0]["id"]]["type"]
            elif deref["offsetrefs"][0]["kind"] == "local":
                typeId = fun["locals"][deref["offsetrefs"][0]["id"]]["type"]
            elif deref["offsetrefs"][0]["kind"] == "param":
                typeId = fun["params"][deref["offsetrefs"][0]["id"]]["type"]
            elif deref["offsetrefs"][0]["kind"] == "array":
                continue
            else:
                continue
            functype = typeDict[typeId]
            while functype["class"] == "pointer" or functype["class"] == "typedef" or functype["class"] == "const_array":
                functype = typeDict[functype["refs"][0]]
            if functype["str"] == "void":
                continue
            iCallsVar.append((deref, fun, tuple(functype["refs"])))

        for deref, func, functypetuple in iCallsVar:
            if functypetuple in funcsbytype:
                funcCandidates = [{"id": x["id"]} for x in funcsbytype[functypetuple]]
                output.setdefault(func["id"], {})
                output[func["id"]][deref["expr"]] = funcCandidates

        return { k:(list(v.keys())[0],[x["id"] for x in list(v.values())[0]]) for k,v in output.items() }

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
        logging.info(f"There are {len(uncalled_funcs)} functions that noone calls")
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

            self.known_funcs_present = set()
            self._get_called_functions(funcs, None, True, True, True)            
            # let's check if there are functions of interest in the subtrees of our functions
            found = False
            for name in self.known_funcs_present:
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
            logging.info(f"AOT_TARGET: {f['name']}: {f['declbody']}")

        logging.info(f"We have {counter} functions that call interesting functions in their subtrees")


        # for f_id in uncalled_funcs:
        #     f = self.fnidmap[f_id]
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
        
        logging.info(f"We have selected the following {len(selected)} functions:")
        for f_id in selected:
            f = self.fnidmap[f_id]
            if f is None:
                logging.error(f"unable to find a function for id {f_id}")
            name = f['name']
            if "abs_location" in f and len(f["abs_location"]) > 0:
                file = os.path.basename(f['abs_location'])
            else:
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
                if "abs_location" in f and len(f["abs_location"]) > 0:
                    file = f['abs_location']
                else:
                    file = f['location']
                
                index = file.find(":")
                if -1 != index:
                    file = file[:index]
                logging.info(f"AOT_UNIQUE_NAME: {name}@{file}")
            else:
                fails += 1
        logging.info(f"Finished generating unique names, fail count {fails}")

    # -------------------------------------------------------------------------

    # the aim of this function is to iterate through all types and within record types 
    # find those that contain pointers
    # then, further analysis is performed to check if we can match the pointer member with
    # a corresponding size member
    def _analyze_types(self):
        logging.info("Beginning type analysis")

        
        self._generate_member_size_info(self.fnmap.get_all(), self.typemap.get_all())
        
        logging.info(f"Type analysis complete. We captured data for {len(self.member_usage_info)} types")
        self._print_member_size_info()
        
        # records_with_pointers = {}

        # checked_record_types = 0
        # for t in self.db["types"]:
        #     if t["class"] == "record":
        #         checked_record_types += 1
        #         member_id = 0
        #         for t_id in t["refs"]:
        #             ref_t = self.typemap[t_id]
        #             ref_t = self._get_typedef_dst(ref_t)
        #             if ref_t["class"] == "pointer":
        #                 # so we have a pointer member
        #                 if t["id"] not in records_with_pointers:
        #                     records_with_pointers[t["id"]] = set()
        #                 records_with_pointers[t["id"]].add(t["refnames"][member_id])

        #             member_id += 1
        # logging.info(f"Type analysis shows {len(records_with_pointers)} record types with pointers out of {checked_record_types} checked record types")

        # keywords = [ "count", "size", "cnt", "len", "length", "sz" ]
        # matched = 0
        # one_to_one_match = 0
        # for t_id in records_with_pointers:
        #     t = self.typemap[t_id]
        #     member_id = 0
        #     matches = set()
        #     for ref_id in t["refs"]:
        #         ref_t = self.typemap[ref_id]
        #         ref_t = self._get_typedef_dst(ref_t)
        #         # the size is likely an integer or unsigned, so it has to be builtin
        #         matches = set()
        #         if ref_t["class"] == "builtin":
        #             name = t["refnames"][member_id]
        #             for key in keywords:
        #                 if key in name.lower():
        #                     matches.add(name)
        #         member_id += 1

        #     if len(matches) > 0:
        #         matched += 1
        #         logging.info(f"For type id {t_id} we have possible matches: {records_with_pointers[t_id]} <-> {matches}")
        #         if len(matches) == 1 and len(records_with_pointers[t_id]) == 1:
        #             one_to_one_match += 1
            
        # logging.info(f"In total, we found matches in {matched} types, including {one_to_one_match} 1-1 matches")
    # -------------------------------------------------------------------------

    # helper functions

    def _print_member_size_info(self):
        count = 0
        logging.info(f"We have info for {len(self.member_usage_info)} structs")
        for t_id in self.member_usage_info:
            name = self.typemap[t_id]["str"]
            logging.info(f"Struct : {name} ")
            index = 0
            for member in self.member_usage_info[t_id]:
                if len(member) > 0:
                    count += 1
                    logging.info(f"\tWe have some data for member {self.typemap[t_id]['refnames'][index]}")
                    if "value" in member:
                        logging.info(f"\t\tvalue: {member['value']}")
                    elif "member_idx" in member:
                        done = False
                        for m in member['member_idx']:
                            done = True
                            name = self.typemap[t_id]['refnames'][m]
                            logging.info(f"\t\tmember_idx: {name}")
                        if not done:
                            logging.info(f"detected member_idx: {member['member_idx']}")

                    elif "name_size" in member:
                        done = False
                        for m in member['name_size']:
                            done = True
                            name = self.typemap[t_id]['refnames'][m]
                            logging.info(f"\t\tname_size: {name}")
                        if not done:
                            logging.info(f"datected name_size: {member['name_size']}")
                    else:
                        logging.info(f"\t\tPrinting raw data {member}")
                index += 1

        logging.info(f"We have found {count} structs with some info on array sizes")

    def _generate_constraints_check(self, var_name, size_constraints):
        str = ""
        if "min_val" in size_constraints:                                            
            str += f"if ({var_name} < {size_constraints['min_val']})" + "{\n"
            str += f"\t{var_name} = {size_constraints['min_val']};\n"
            str += "}\n"
        if "max_val" in size_constraints:                                            
            str += f"if ({var_name} > {size_constraints['max_val']})" + "{\n"
            str += f"\t{var_name} %= {size_constraints['max_val']};\n"
            str += f"\t{var_name} += 1;\n"
            str += "}\n"
        return str

    # use member_type_info to get the right member init ordering for a record type       
    # return a list consisting of member indices to generate init for
    def _get_members_order(self, t):
        ret = []
        size_constraints = []
        if t['class'] != 'record':
            return None, None
        ret = [i for i in range(len(t['refnames']))]
        size_constraints = [ {} for i in range(len(t['refnames'])) ]

        t_id = t['id']

        if t_id not in self.member_usage_info:
            return ret,size_constraints
        
        fields_no = len(t['refnames'])
        for i in range(fields_no):
            field_name = t['refnames'][i]
            
            if field_name == "__!attribute__" or field_name == "__!anonrecord__" or \
                field_name == "__!recorddecl__" or field_name == "__!anonenum__":
                    continue
        
            is_in_use = self._is_member_in_use(t, t['str'], i)
            if is_in_use:
                # now we know that the member is in use, let's check if we have some info for it
                usage_info = self.member_usage_info[t_id][i]
                if len(usage_info) == 0:
                    continue

                # we have some usage info for this member
                size_member_index = None
                match = False
                if "name_size" in usage_info:
                    if len(usage_info["name_size"]) == 1:
                        size_member_index = next(iter(usage_info["name_size"]))
                        match = True
                    else:
                        # we have more than 1 candidates, let's see if 
                        # some additional info could help
                        # first, we check if the same member is a single member for member_idx
                        if "member_idx" in usage_info and len(usage_info["member_idx"]) == 1:
                            for m in usage_info["name_size"]:
                                item = next(iter(usage_info["member_idx"]))                                
                                if item[0] == t_id and m == item[1]:
                                    size_member_index = m
                                    match = True
                                    break
                        # if no single match found, also check "member_size"
                        if not match and "member_size" in usage_info and len(usage_info["member_size"]) == 1:
                            for m in usage_info["name_size"]:
                                item = next(iter(usage_info["member_size"]))                                
                                if item[0] == t_id and m == item[1]:
                                    size_member_index = m
                                    match = True
                                    break
                    if match:
                        # either a single name_size or multiple name_size but a single
                        # member_idx or a single member_size that matches one of the name_size ones
                        size_constraints[i]['size_member'] = size_member_index
                        if size_member_index not in size_constraints:
                            size_constraints[size_member_index] = {}
                        # since we use one member as a size for another, the value range needs to be meaningful
                        size_constraints[size_member_index]["min_val"] = 1
                        if "max_val" not in size_constraints[size_member_index]:
                            max_val = self.array_init_max_size
                            if "value" in usage_info:
                                val = usage_info["value"]
                                if val > 0:
                                    if val != max_val:
                                        # leverage the fact that we noticed array reference at a concrete offset 
                                        max_val = val
                            size_constraints[size_member_index]["max_val"] = max_val
                        size_member_index = [ size_member_index ]
                        
                    else:
                        size_member_index = usage_info["name_size"]
                    match = True

                if match is False and "member_idx" in usage_info:
                    item = usage_info["member_idx"]
                    if len(item) == 1:
                        item = next(iter(item))
                        if t_id == item[0]: 
                            size_member_index = item[1]
                            size_constraints[i]["size_member_idx"] = size_member_index
                            if size_member_index not in size_constraints:
                                size_constraints[size_member_index] = {}
                            # since we use one member as a size for another, the value range needs to be meaningful                        
                            size_constraints[size_member_index]["min_val"] = 1
                            if "max_val" not in size_constraints[size_member_index]:
                                max_val = self.array_init_max_size
                                if "value" in usage_info:
                                    val = usage_info["value"]
                                    if val > 0:
                                        if val != max_val:
                                            #leverage the fact that we noticed array reference at a concrete offset 
                                            max_val = val
                                size_constraints[size_member_index]["max_val"] = max_val
                            size_member_index = [ size_member_index ]

                            match = True

                if match is False and "member_size" in usage_info:
                    item = usage_info["member_size"]
                    if len(item) == 1:
                        item = next(iter(item))
                        if t_id == item[0]: 
                            size_member_index = item[1]
                            size_constraints[i]["size_member_idx"] = size_member_index
                            if size_member_index not in size_constraints:
                                size_constraints[size_member_index] = {}
                            # since we use one member as a size for another, the value range needs to be meaningful                        
                            size_constraints[size_member_index]["min_val"] = 1
                            if "max_val" not in size_constraints[size_member_index]:
                                max_val = self.array_init_max_size
                                if "value" in usage_info:
                                    val = usage_info["value"]
                                    if val > 0:
                                        if val != max_val:
                                            #leverage the fact that we noticed array reference at a concrete offset 
                                            max_val = val
                                size_constraints[size_member_index]["max_val"] = max_val
                            size_member_index = [ size_member_index ]

                            match = True

                if match is False and "value" in usage_info:
                    val = usage_info["value"]
                    if (val < 0):
                        val = -val
                    if val != 0:
                        # val would be the largest const index used on an array + 1 (so it's array size)
                        size_constraints[i]["size_value"] = val

                if size_member_index is not None:
                    current_index = i
                    for sm_index in size_member_index:
                        if sm_index > current_index:
                            # swap members such that the size member is initialized before the buffer member
                            ret[current_index] = sm_index
                            ret[sm_index] = current_index
                            logging.info(f"Swapping members {current_index} and {sm_index} in type {t['str']}")                
                            current_index = sm_index

                if "index" in usage_info:
                    logging.info(f"Index detected in usage info for member {field_name}")
                    max_val = -1
                    if "max_val" in size_constraints[i]:
                        max_val = size_constraints[i]["max_val"]
                    if (max_val == -1) or ((usage_info["index"] - 1) < max_val):
                        # the 'index' member is collected based on a const-size array reference
                        # therefore if one exists, we are certain that the value is no greater than the size - 1
                        size_constraints[i]["max_val"] = usage_info["index"] - 1 
                        
                        if "min_val" not in size_constraints: 
                            size_constraints[i]["min_val"] = 0

        return ret, size_constraints

    def _is_size_type(self, t):
        ints = {'char', 'signed char', 'unsigned char', 'short', 'unsigned short', 'int', 'unsigned int',
                'long', 'unsigned long', 'long long', 'unsigned long long', 'unsigned __int128'}
        t = self._get_typedef_dst(t)
        if t["str"] in ints:
            return True
        return False

    def _get_record_type(self,base_type):
        # remove typedef to pointer type
        base_type = self._get_typedef_dst(base_type)
        # remove pointer
        base_type = self.typemap[self._get_real_type(base_type['id'])]
        # remove typedef to record type)
        base_type = self._get_typedef_dst(base_type)
        return base_type

    def _find_local_init_or_assign(self, local_id, ord, func):
        matching_derefs = []
        for deref in func["derefs"]:
            if deref["kind"] in ["init","assign"]:
                lhs = deref["offsetrefs"][0]
                if lhs["kind"] == "local" and lhs["id"] == local_id and deref["ord"] < ord:
                    matching_derefs.append(deref)
        return matching_derefs
    
    def _is_pointer_like_type(self,t):
        t = self._get_typedef_dst(t)
        # normal pointer
        if t["class"] == "pointer":
            return True
        # address held in 64 int
        if self._is_size_type(t) and t["size"] == 64:
            return True
        return False

    # function generates usage info for record members
    # we are looking for struct types with pointer members and try to find the corresponding
    # member with the same type that may represent the pointer's size
    # The extra info we collect:
    # 
    # for pointer-like members:
    # - ['name_size']  : other struct members that can represent size -> detected by name, e.g., s->array <=> s->array_size
    # - ['member_idx'] : other struct members that can represent size -> detected by index use, e.g., s->array[s->member]
    # - ['value']      :constant sizes -> detected by the use of const indices, e.g., s->array[20]
    # - ['member_size']: other struct members taht can represent size -> detected by comparison, e.g. for (; s->index < 10; ), if (s->index <= 9)
    # for size-like members:
    # - ['index']      : upper limit for members used as an index in a const array (any), e.g. array[s->index], where array is of size 20
    def _generate_member_size_info(self, funcs, types):
        logging.info(f"will generate size info for {len(funcs)} funcs and {len(types)} types")
        
        for func in funcs:
            logging.info(f"processing {func['name']}")
            derefs = func["derefs"]
            for deref in derefs:
                # get info from 'array' kind derefs, ignore complicated cases
                if deref["kind"] == "array" and deref["basecnt"] == 1:
                    base_offsetref = deref["offsetrefs"][0]
                    # info for array members
                    if base_offsetref["kind"] == "member":
                        member_deref = derefs[base_offsetref["id"]]
                        record_type = self._get_record_type(self.typemap[member_deref["type"][-1]])
                        record_id = record_type["id"]
                        member_id = member_deref["member"][-1]
                        member_type = self.typemap[record_type["refs"][member_id]]
                        member_type = self._get_typedef_dst(member_type)
                        # we only care about poiners
                        if self._is_pointer_like_type(member_type):
                            # add info about member usage (implicit by existence)
                            if record_id not in self.member_usage_info:
                                self.member_usage_info[record_id] = [{} for k in record_type["refs"]]
                            member_data = self.member_usage_info[record_id][member_id]

                            # add info about potential size
                            if deref["offset"] != 0:
                                if "value" not in member_data:
                                    member_data["value"] = deref["offset"]+1
                                else:
                                    member_data["value"] = max(member_data["value"], deref["offset"]+1)
                            # add info about potential index member
                            for index_offsetref in deref["offsetrefs"][1:]:
                                # same base member index
                                if index_offsetref["kind"] == "member":
                                    size_deref = derefs[index_offsetref["id"]]
                                    size_record_type = self._get_record_type(self.typemap[size_deref["type"][-1]])
                                    size_record_id = size_record_type["id"]
                                    size_member_id = size_deref["member"][-1]
                                    size_member_type = self.typemap[size_record_type["refs"][size_member_id]]
                                    size_member_type = self._get_typedef_dst(size_member_type)
                                    if self._is_size_type(size_member_type):
                                        if "member_idx" not in member_data:
                                            member_data["member_idx"] = set()
                                        member_data["member_idx"].add((size_record_id,size_member_id))
                            # add info about potential size member
                            if len(deref["offsetrefs"]) == 2:
                                index_offsetref = deref["offsetrefs"][1]
                                item = next(cs for cs in func["csmap"] if cs["id"] == deref["csid"])
                                if "cf" in item and item["cf"] in ["do","while","for","if"]:
                                    # find condition
                                    for cderef in derefs:
                                        if cderef["kind"] == "cond" and cderef["offset"] == deref["csid"]:
                                            if len(cderef["offsetrefs"]) == 1 and cderef["offsetrefs"][0]["kind"] == "logic":
                                                lderef = derefs[cderef["offsetrefs"][0]["id"]]
                                                if lderef["offset"] in [10,12,15] and len(lderef["offsetrefs"]) == 2:
                                                    if index_offsetref == lderef["offsetrefs"][0]:
                                                        size_offsetref = lderef["offsetrefs"][1]
                                                        if size_offsetref["kind"] == "integer":
                                                            size = size_offsetref["id"]
                                                            if lderef["offset"] == 12:
                                                                size+=1
                                                            if "value" not in member_data:
                                                                 member_data["value"] = size
                                                            else:
                                                                member_data["value"] = max(member_data["value"], size)
                                                        if size_offsetref["kind"] == "member":
                                                            size_deref = derefs[size_offsetref["id"]]
                                                            size_record_type = self._get_record_type(self.typemap[size_deref["type"][-1]])
                                                            size_record_id = size_record_type["id"]
                                                            size_member_id = size_deref["member"][-1]
                                                            size_member_type = self.typemap[size_record_type["refs"][size_member_id]]
                                                            size_member_type = self._get_typedef_dst(size_member_type)
                                                            if self._is_size_type(size_member_type):
                                                                if "member_size" not in member_data:
                                                                    member_data["member_size"] = set()
                                                                member_data["member_size"].add((size_record_id,size_member_id))
                # add info about members as index to const arrays
                if deref["kind"] == "array" and deref["basecnt"] == 1 and len(deref["offsetrefs"]) == 2:
                    base_offsetref = deref["offsetrefs"][0]
                    index_offsetref = deref["offsetrefs"][1]
                    if index_offsetref["kind"] == "member":
                        # try find array size
                        size = 0
                        if base_offsetref["kind"] == "member":
                            base_deref = derefs[base_offsetref["id"]]
                            base_record_type = self._get_record_type(self.typemap[base_deref["type"][-1]])
                            base_member_id = base_deref["member"][-1]
                            base_member_type = self._get_typedef_dst(self.typemap[base_record_type["refs"][base_member_id]])
                            if base_member_type["class"] == "const_array":
                                size = self._get_const_array_size(base_member_type)
                        elif base_offsetref["kind"] == "global":
                            global_deref = self.globalsidmap[base_offsetref["id"]]
                            global_type = self._get_typedef_dst(self.typemap[global_deref["type"]])
                            if global_type["class"] == "const_array":
                                size = self._get_const_array_size(global_type)
                        elif base_offsetref["kind"] == "local":
                            local_deref = func["locals"][base_offsetref["id"]]
                            local_type = self._get_typedef_dst(self.typemap[local_deref["type"]])
                            if local_type["class"] == "const_array":
                                size = self._get_const_array_size(local_type)
                        if size != 0:
                            # add size info
                            index_deref = derefs[index_offsetref["id"]]
                            index_record_type = self._get_record_type(self.typemap[index_deref["type"][-1]])
                            index_record_id = index_record_type["id"]
                            index_member_id = index_deref["member"][-1]
                            if index_record_id not in self.member_usage_info:
                                self.member_usage_info[index_record_id] = [{} for k in index_record_type["refs"]]
                            index_data = self.member_usage_info[index_record_id][index_member_id]
                            if "index" in index_data:
                                index_data["index"] = max(size,index_data["index"])
                            index_data["index"] = size
        
        for _t in types:
            t = self._get_record_type(_t)
            if t["class"] == "record":
                # try guessing size member from name
                # do only once
                record_type = t                
                record_id = t["id"]

                for member_id in range(len(record_type["refs"])):
                    m_t = self.typemap[record_type["refs"][member_id]]
                    # looking for a pointer struct members
                    if self._is_pointer_like_type(m_t):
                         
                        if record_id not in self.member_usage_info:
                            self.member_usage_info[record_id] = [{} for k in record_type["refs"]]
                        member_data = self.member_usage_info[record_id][member_id]

                        if "name_size" not in member_data:
                            sizecount = 0
                            sizes = []
                            sizematch = ["size", "len", "num", "count", "sz", "n_", "cnt", "length"]
                            for size_member_id in range(len(record_type["refs"])):
                                size_type = self.typemap[record_type["refs"][size_member_id]]
                                if self._is_size_type(size_type):
                                    # name matching
                                    member_name = record_type["refnames"][member_id]
                                    size_name = record_type["refnames"][size_member_id]
                                    if member_name in size_name:
                                        for match in sizematch:
                                            if match in size_name.replace(member_name,'').lower():
                                                sizecount+=1
                                                sizes.append(size_member_id)
                                                break
                            # TODO: solve priority instead of adding all maybe
                            if sizecount > 1:
                                pass
                            if len(sizes) > 0:
                                member_data["name_size"] = set()
                                member_data["name_size"] |= set(sizes)
                                
    #--------------------------------------------------------------------------


    def adjust_funcs_lib(self):
        #if self.lib_funcs_file == None:
        #    return True
        if 0 == len(self.lib_funcs):
            return True

        contents = ""
        with open(f"{self.out_dir}/aot_lib.h", "r") as f:
            contents = f.readlines()
        with open(f"{self.out_dir}/aot_lib.h", "w") as f:    
            f.write(self._get_header_guard("aot_lib.h")) 
            f.write(
                "\n// Enable user-defined library functions specified in lib-funcs-file\n\n")
            for func_name in self.lib_funcs:
                if func_name in self.known_funcs_present: 
                    f.write(f"#define AOT_{func_name.upper()}\n")
            f.writelines(contents)
            f.write("\n#endif")
    # -------------------------------------------------------------------------

    def _func_contains_assembly(self, f):
        if "asm" not in f:
            return False
        if len(f["asm"]) == 0:
            return False
        return True

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

    def create_indices(self):
        # moving this functionality out of the library as it's specific to
        # db.json

        self.funcs_tree_funrefs = None
        self.funcs_tree_funrefs_no_known = None
        self.funcs_tree_funrefs_no_asm = None
        self.funcs_tree_funrefs_no_known_no_asm = None
        self.funcs_tree_calls = None
        self.funcs_tree_calls_no_known = None
        self.funcs_tree_calls_no_asm = None
        self.funcs_tree_calls_no_known_no_asm = None

        self.types_tree_refs = None
        self.types_tree_usedrefs = None
        self.globs_tree_globalrefs = None

        self.known_funcs_ids = set()

        # create DB indices
        if self.import_json:
            collections = ["funcs", "types", "globals", "sources", "funcdecls", "unresolvedfuncs"]
            fields = ["id", "name", "fid", "refs", "usedrefs", "decls", "class", "types", "calls", "funrefs", "fids", "globalrefs",
            "linkage", "body", "funcdecls", "hash", "implicit", "location", "abs_location", "declbody", "inline", "str", "type", "size", 
            "hasinit", "derefs", "union", "def", "unpreprocessed_body", "refnames", "bitfields", "locals", "signature"]
            for c in collections:
                for f in fields:
                    self.db.create_index(c, f)

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

        json_data = None
        if self.import_json is not None:
            # we create recursive hierarchies data off-line and from JSON file
            # during import to DB (since only at that point we have the file available)
            logging.info("Going to create recursive dependencies cache")
            json_data = self.db.json_data # there is a chance we already loaded the data
                                          # for import to the db
            
            if json_data is None:
                with open(self.import_json, "r") as jfile:
                    logging.info("Loading JSON db to RAM")
                    json_data = json.load(jfile)
        
#####################################
        known_functions_updated = False
        if self.lib_funcs_file is not None:

            _fids, _funcs = self._get_funcs_from_a_text_file(self.lib_funcs_file)
            self.lib_funcs_ids |= _fids
            self.known_funcs_ids |= _fids
            for name in _funcs:
                self.lib_funcs.append(name)
            
            if self.import_json is None:
                known_functions_updated = True
                logging.info("New known functions detected: need to re-calculate the caches")
        else:
            logging.info("No lib functions specified: getting the data from db")
               
#####################################

        # try to get what we can from the db        
        known_data = self.db.create_local_index("known_data", "version")

        if self.import_json is not None:
            known_data = None
        else:
            known_data = known_data[self.version]
        if known_data is None:
            logging.warning(
                "The version stored in the db is not the current version - will not use known data")
        else:
            self.builtin_funcs_ids = set()
            self.all_funcs_with_asm = set()
            self.static_funcs_map = {}
            
            static_funcs = self.db.create_local_index("static_funcs_map", "id").get_all()
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
            self.source_root = known_data['source_root']
        logging.info(f"Version is {self.version}, source root is {self.source_root}")


        if self.always_inc_funcs_file is None:
            logging.info("No always include functions file specified: getting data from the db")
        else:
            logging.info(
                "Will load always include functions from a file")
            _fids, _funcs = self._get_funcs_from_a_text_file(self.always_inc_funcs_file)
            self.always_inc_funcs_ids |= _fids
            logging.info(f"Intially we have {len(self.always_inc_funcs_ids)} functions to include")
       
        if self.known_funcs_file is None:
            logging.info("No known_functions file specified: getting the data from the db")

        else: #if self.known_funcs_file is not None:
            load = True
            # TODO: keeping this for now for backwards compatibility, but
            # the information stored in JSON files should now be in the database
            if self.known_funcs_file.endswith("json"):
                logging.info(
                    "Will load known functions and types from a JSON file")
                with open(self.known_funcs_file, "r") as f:
                    data = json.load(f)
                    ver = data["version"]
                    if ver != self.version:
                        logging.warning(
                            "The version of the JSON file doesn't match the current version.")
                    else:
                        load = False
                        self.known_funcs_ids = set(data["func_ids"])
                        self.builtin_funcs_ids = set(data['builtin_ids'])
                        self.all_funcs_with_asm = set(data['asm_ids'])
                        self.static_funcs_map = data['static_funcs']
                        
            if load: # this is expected to happen only once while importing a new JSON to the database
                logging.info(
                    "Will discover known functions and types based on a list of function names")
                
                _fids, _funcs = self._get_funcs_from_a_text_file(self.known_funcs_file)
                self.known_funcs_ids |= _fids

                # get builtin func ids, funcs with asm and a map of static funcs
                logging.info("Getting builtin functions")
                prefix = "__builtin"

                if json_data is not None:
                    funcs = json_data['funcs']
                    logging.info("using data from local json file")
                else:
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

                if json_data is not None:
                    funcdecls = json_data['funcdecls']
                else:
                    funcdecls = self.db["funcdecls"]
                for f in funcdecls:
                    n = f["name"]
                    if n.startswith(prefix):
                        self.builtin_funcs_ids.add(f["id"])
                
                if json_data is not None:
                    unresolved = json_data['unresolvedfuncs']
                else:
                    unresolved = self.db['unresolvedfuncs']
                for f in unresolved:
                    n = f["name"]
                    if n.startswith(prefix):
                        self.builtin_funcs_ids.add(f["id"])

                tmp_static_funcs_map = []
                for f_id in self.static_funcs_map:
                    item = {"id": f_id, "fids": self.static_funcs_map[f_id]}
                    tmp_static_funcs_map.append(item)
                self.db.store_many_in_collection("static_funcs_map", tmp_static_funcs_map)

                src_root = ""
                if self.source_root is not None:
                    src_root = self.source_root
                known_data = {
                    "version": self.version,
                    "func_ids": list(self.known_funcs_ids),
                    "builtin_ids": list(self.builtin_funcs_ids),
                    "asm_ids": list(self.all_funcs_with_asm),
                    "lib_funcs": list(self.lib_funcs),
                    "lib_funcs_ids": list(self.lib_funcs_ids),
                    "always_inc_funcs_ids": list(self.always_inc_funcs_ids),
                    "source_root": src_root 
                }
                filename = f"{self.known_funcs_file}.json"
                filename = os.path.basename(filename)
                filename = f"{os.getcwd()}/{filename}"

                logging.info("Storing known data in the db")
                # TODO: we only store that data in the db really during the first import
                # currently it's stored whenever the user provides a test file
                self.db.store_in_collection("known_data", known_data)

    
        if self.import_json is not None:
            # we create recursive hierarchies data off-line and from JSON file
            # during import to DB (since only at that point we have the file available)
            logging.info("Going to create recursive dependencies cache")

            # json_data is initialized above
            funcs = json_data["funcs"]
            types = json_data["types"]
            globs = json_data["globals"]

            # make all recursive queries we might ever need
            logging.info("Performing recursive queries for all funcs")
            known_asm = set()
            known_asm |= set(self.known_funcs_ids)
            known_asm |= set(self.all_funcs_with_asm)


            funcs_size = len(funcs) + len(json_data['funcdecls']) + len(json_data['unresolvedfuncs'])
            self.uncs_tree_funrefs = self._create_recursive_cache(funcs, funcs_size, "id", "funrefs", Generator.FUNCS_REFS, set())
            self.funcs_tree_funrefs_no_known = self._create_recursive_cache(funcs, funcs_size, "id", "funrefs", Generator.FUNCS_REFS_NO_KNOWN, set(self.known_funcs_ids))
            self.funcs_tree_funrefs_no_asm = self._create_recursive_cache(funcs, funcs_size, "id", "funrefs", Generator.FUNCS_REFS_NO_ASM, set(self.all_funcs_with_asm))
            self.funcs_tree_funrefs_no_known_no_asm = self._create_recursive_cache(funcs, funcs_size, "id", "funrefs", Generator.FUNCS_REFS_NO_KNOWN_NO_ASM, known_asm)
            self.funcs_tree_calls = self._create_recursive_cache(funcs, funcs_size, "id", "calls", Generator.FUNCS_CALLS, set())
            self.funcs_tree_calls_no_known = self._create_recursive_cache(funcs, funcs_size, "id", "calls", Generator.FUNCS_CALLS_NO_KNOWN, set(self.known_funcs_ids))
            self.funcs_tree_calls_no_asm = self._create_recursive_cache(funcs, funcs_size, "id", "calls", Generator.FUNCS_CALLS_NO_ASM, set(self.all_funcs_with_asm))
            self.funcs_tree_calls_no_known_no_asm = self._create_recursive_cache(funcs, funcs_size, "id", "calls", Generator.FUNCS_CALLS_NO_KNOWN_NO_ASM, known_asm)

            self.types_tree_refs = self._create_recursive_cache(types, len(types), "id", "refs", Generator.TYPES_REFS, set())
            self.types_tree_usedrefs = self._create_recursive_cache(types, len(types), "id", "usedrefs", Generator.TYPES_USEDREFS, set())
            self.globs_tree_globalrefs = self._create_recursive_cache(globs, len(globs), "id", "globalrefs", Generator.GLOBS_GLOBALREFS, set())

            del funcs
            del types
            del globs
            del json_data

            logging.info("Storing completed")
        else:

            # load recursive caches from the database
            logging.info("Create indices for recursive query caches")

            # recursive queries are handled by csr_matix objects 
            # we have the necessary data for those objects stored in the db
            self.funcs_tree_funrefs = self._create_cache_matrix(self.db, Generator.FUNCS_REFS)
            self.funcs_tree_calls = self._create_cache_matrix(self.db, Generator.FUNCS_CALLS)

            funcs = []
            known_asm = set()
            funcs_size = 0
            if known_functions_updated:
                known_asm |= set(self.known_funcs_ids)
                known_asm |= set(self.all_funcs_with_asm)
                for f in self.db["funcs"]:
                    funcs.append(f)
                a, b = self.funcs_tree_funrefs.shape
                funcs_size = a

            if not known_functions_updated:
                self.funcs_tree_funrefs_no_known = self._create_cache_matrix(self.db, Generator.FUNCS_REFS_NO_KNOWN) 
                self.funcs_tree_calls_no_known = self._create_cache_matrix(self.db, Generator.FUNCS_CALLS_NO_KNOWN)
            else:
                self.funcs_tree_funrefs_no_known = self._create_recursive_cache(funcs, funcs_size, "id", "funrefs", Generator.FUNCS_REFS_NO_KNOWN, set(self.known_funcs_ids))
                self.funcs_tree_calls_no_known = self._create_recursive_cache(funcs, funcs_size, "id", "calls", Generator.FUNCS_CALLS_NO_KNOWN, set(self.known_funcs_ids))

            self.funcs_tree_funrefs_no_asm = self._create_cache_matrix(self.db, Generator.FUNCS_REFS_NO_ASM)
            self.funcs_tree_calls_no_asm = self._create_cache_matrix(self.db, Generator.FUNCS_CALLS_NO_ASM)
            
            if not known_functions_updated:
                self.funcs_tree_funrefs_no_known_no_asm = self._create_cache_matrix(self.db, Generator.FUNCS_REFS_NO_KNOWN_NO_ASM)
                self.funcs_tree_calls_no_known_no_asm = self._create_cache_matrix(self.db, Generator.FUNCS_CALLS_NO_KNOWN_NO_ASM)
            else:
                self.funcs_tree_funrefs_no_known_no_asm = self._create_recursive_cache(funcs, funcs_size, "id", "funrefs", Generator.FUNCS_REFS_NO_KNOWN_NO_ASM, known_asm)           
                self.funcs_tree_calls_no_known_no_asm = self._create_recursive_cache(funcs, funcs_size, "id", "calls", Generator.FUNCS_CALLS_NO_KNOWN_NO_ASM, known_asm)           
               
            self.types_tree_refs = self._create_cache_matrix(self.db, Generator.TYPES_REFS)
            self.types_tree_usedrefs = self._create_cache_matrix(self.db, Generator.TYPES_USEDREFS)
            self.globs_tree_globalrefs = self._create_cache_matrix(self.db, Generator.GLOBS_GLOBALREFS)

            self._get_called_functions(self.always_inc_funcs_ids)
            logging.info(f"Recursively we have {len(self.always_inc_funcs_ids)} functions to include")


        # import all data init constraints
        if self.init_file:
            logging.info("Loading data init file")
            # the user specified a JSON file with data init constraints
            with open(self.init_file, "r") as f:
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
                logging.info(f"User-provided init data loaded with {len(self.init_data)} entries")

                if self.import_json:
                    # store that data in the db
                    data = [ self.init_data[x] for x in self.init_data ]
                    self.db.store_many_in_collection("init_data", data)
        else:
            # load init data from db
            self.init_data = self.db.create_local_index("init_data", "name")

   
    # -------------------------------------------------------------------------

    def _create_cache_matrix(self, db, collection_name):
        logging.info(f"Generating cache matrix for collection {collection_name}")
        index = self.db.create_local_index(collection_name, "name")
        data = index[Generator.DATA]
        row_ind = index[Generator.ROW_IND]
        col_ind = index[Generator.COL_IND]
        np_data = np.array(data["data"])
        np_row_ind = np.array(row_ind["data"])
        np_col_ind = np.array(col_ind["data"])
        size = index[Generator.MATRIX_SIZE]['data']
        
        matrix = csr_matrix((np_data, (np_row_ind, np_col_ind)), shape=(size, size))

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
        matrix = csr_matrix((np_data, (np_row_ind, np_col_ind)), shape=(size, size))
        logging.info("Matrix created")
        # need to break the matrix data into 3 due to the limit of a single document size in db
        self.db.store_in_collection(collection_name, {"name": Generator.DATA, "data": data})
        self.db.store_in_collection(collection_name, {"name": Generator.ROW_IND, "data": row_ind})
        self.db.store_in_collection(collection_name, {"name": Generator.COL_IND, "data": col_ind})
        self.db.store_in_collection(collection_name, {"name": Generator.MATRIX_SIZE, "data": size})

        return matrix

    # -------------------------------------------------------------------------

    @staticmethod
    def _graph_dfs(csr_matrix, item):
        nodes = depth_first_order(csr_matrix, item, directed=True, return_predecessors=False)
        nodes_int = [ n.item() for n in nodes ]
        return nodes_int[1:]

    # make recursive in-memory query - this is used e.g. to get a subtree of called functions,
    # or type dependencies, etc.
    # the method itself is not recursive for performance reasons (way too slow on large data sets)
    @staticmethod
    def _recursive_inmem_query(data, start_obj, match_from, match_to, cutoff):
        if match_from not in start_obj:
            return []
        to_process = []
        to_process.append(start_obj[match_from])
        _result_id = start_obj[match_from]
        _results = []
        while (len(to_process)):
            item_id = to_process.pop()

            if item_id not in data:
                continue

            item = data[item_id]
            if match_to not in item:
                continue
        
            cutoff.add(item_id) # prevent infinite loops

            match_list = item[match_to]
            for member in match_list:
                if member in cutoff:
                    continue
                _results.append(member)
                if member in data:
                    starter = data[member]
                    if match_from in starter:                        
                        to_process.append(starter[match_from]) # store the item for further processing
        
        return _result_id, _results
    # -------------------------------------------------------------------------

    # Remove those functions that are known (e.g. memcpy)
    def _filter_out_known_functions(self, functions, discover=False):
        if discover:
            for f_id in functions:
                if f_id in self.known_funcs_ids:
                    self.known_funcs_present.add(self._get_function_name(f_id))

        functions.difference_update(set(self.known_funcs_ids))
        return functions

    # -------------------------------------------------------------------------

    def _filter_out_builtin_functions(self, functions):
        functions.difference_update(set(self.builtin_funcs_ids))
        return functions

    # -------------------------------------------------------------------------

    def _filter_out_asm_functions(self, functions):
        if self.include_asm:
            return functions
        functions.difference_update(set(self.all_funcs_with_asm))
        return functions

    # -------------------------------------------------------------------------

    # comment out inline assembly code and keep stats
    def _filter_out_asm_inlines(self, fid, body, file):
        if self.include_asm:
            return body

        tmp = body
        tmp = tmp.replace("asm volatile", "//asm volatile")
        tmp = tmp.replace("asm (", "//asm (")
        tmp = tmp.replace("asm(", "//asm(")

        if tmp != body:
            # we have replaced some inline asm
            diff = difflib.unified_diff(body.split("\n"), tmp.split("\n"), n=0)
            if fid not in self.known_funcs_ids:
                self.funcs_with_asm[fid] = {"file": file, "diff": diff}

        return tmp

    # -------------------------------------------------------------------------

    def _filter_out_asm_in_fdecl(self, decl):
        if not self.include_asm and ' asm(' in decl:
            index = decl.find(' asm(')
            end = decl[index:].find(')') + index
            logging.info(
                f"Found asm in function end is {end} copy len is {len(decl)} copy is {decl}")
            if end == len(decl) - 1:
                # the declation end with the asm clause -> that's what we're looking for
                decl = decl[:index] + "/*" + decl[index:end + 1] + "*/"
        return decl

    # -------------------------------------------------------------------------

    # Currently types in db.json which are used in const and non-const context appear
    # separately. This function is supposed to discover those duplicates and create
    # a local map for a quicker discovery
    # Since we iterate over all type objects we will use that to find implicit types.
    # Implicit types are those which are provided by a compiler.
    def discover_type_duplicates(self):
        logging.info("getting dups")
        hash_to_ids = {}
        for t in self.db["types"]:
            tid = t["id"]

            if "def" not in t:
                continue

            if t["class"] != "record":
                h = hash(t["def"])

                # these are not strictly duplicates, but we also need to have a special handler for
                # a case in which a single typedef with a new type definition has several names like:
                # typedef struct a { int aa; } x, y;
                # In that case, db.json stores 2 separate entries for x and y, which both have a single ref
                # to struct a -> we need to know about this in order to correctly emit the code, i.e. to
                # generate a single typedef, not two typedefs
                if t["class"] == "typedef" and "decls" in t and len(t["decls"]) != 0:
                    # assuming a typedef has exactly one ref
                    dst_tid = t["refs"][0]
                    if dst_tid not in self.identical_typedefs:
                        self.identical_typedefs[dst_tid] = set()

                    self.identical_typedefs[dst_tid].add(tid)

            else:
                # in case of record, take the type's hash - this is needed because of
                # record forwards that can create additional content in the definition and thus
                # make two identical types look different
                parts = t["hash"].split(":")
                h = ""
                for i in range(len(parts)):
                    if i == 1:
                        # skip qualifier
                        continue
                    h += parts[i]

            if h not in hash_to_ids:
                hash_to_ids[h] = [tid]
            else:
                hash_to_ids[h].append(tid)

            if "implicit" in t:
                if t["implicit"]:
                    self.implicit_types.add(tid)

        logging.info("We've got {} implicit types".format(
            len(self.implicit_types)))

        hashes_to_remove = []
        for h, ids in hash_to_ids.items():
            if len(ids) == 1:
                hashes_to_remove.append(h)

        for h in hashes_to_remove:
            hash_to_ids.pop(h)

        for h in hash_to_ids:
            for id in hash_to_ids[h]:
                self.dup_types[id] = hash_to_ids[h]
        cnt = 0
        for tid in self.identical_typedefs:
            if len(self.identical_typedefs[tid]) > 1:
                cnt += 1
        logging.info(
            f"Discovered {cnt} identical typedefs, dict size is {len(self.identical_typedefs)}")

        logging.info("Done, found {} dups".format(len(self.dup_types)))

    # -------------------------------------------------------------------------

    # The purpose of this function is to create a mapping between a type T and a type
    # containing the definition of the type T. The other direction is easy to get as
    # it comes directly from the "decls" field.
    def discover_internal_types(self):

        for t in self.db["types"]:

            if "decls" in t and len(t["decls"]) > 0:
                for i in t["decls"]:
                    if self.used_types_only and t["class"] == "record":
                        dst_tid = t["usedrefs"][i]
                    else:
                        dst_tid = t["refs"][i]
                    # ref could be -1 is a ref is unused (the usedrefs case)
                    if -1 == dst_tid:
                        continue
                    tid = t["id"]
                    if dst_tid not in self.internal_types:
                        self.internal_types[dst_tid] = set()

                    self.internal_types[dst_tid].add(tid)

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
            for fid in fids:
                srcs.append(self.srcidmap[fid])
        else:
            # if fids not present for some reason, we still have fid
            srcs.append(self.srcidmap[fid])

        if "abs_location" in function and len(function["abs_location"]) > 0:
            loc = function["abs_location"]
        else:
            loc = function["location"]
        if self.source_root is not None and self.source_root and len(self.source_root) > 0:
            if loc.startswith("./"): 
                loc = self.source_root + loc[1:]
            elif not loc.startswith("/"):
                loc = self.source_root + "/" + loc
                
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
            shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")
            sys.exit(1)

    # -------------------------------------------------------------------------

    # given a function, find (recursively) all functions that is calls which are inside
    # same module; this is done with the use of information from BAS
    def _get_internal_funcs(self, f, internal_funcs, external_funcs):
        base_fid = f["id"]

        if not self.include_asm and base_fid in self.all_funcs_with_asm:
            logging.info(f"Skipping further exploration for a function with asm: {self._get_function_name(base_fid)}")
            return
        if base_fid in self.known_funcs_ids:
            logging.info("Skipping further exploration for a known function")
            return
   
        logging.debug("Processing function {}".format(base_fid))
        funrefs = set(f["funrefs"])

        # in additiom to funrefs, there might be an implicit dependency to other functions
        # coming from globals and types
        internal_defs = set()
        type_refs = self._get_types_in_funcs([base_fid], internal_defs)
        #skip_list = set(f)
        #skip_list |= internal_funcs
        #skip_list |= external_funcs
        funrefs |= self._get_funcs_from_types(type_refs)#, skip_list)

        global_refs = set()
        if "globalrefs" in f:
            global_refs |= set(f["globalrefs"])
        global_refs |= self._get_globals_from_types(type_refs)
        global_refs |= self._get_globals_from_globals(global_refs)

        funrefs |= self._get_funcs_from_globals(global_refs)
        for fid in funrefs:
            logging.debug("checking funref {} ".format(fid))
            ext = False  # deciding if the function is external or not

            if fid in self.always_inc_funcs_ids:
                logging.info(f"Including internal func {fid}")
            else:
                if self.cut_off == Generator.CUT_OFF_MODULE:
                    if fid not in self.fid_to_mods:
                        ext = True
                        # fid will not be in fid_to_mods if it's an unresolved function in db.json
                    else:    
                        # internal functions are the ones residing in the same module
                        mods = self.fid_to_mods[fid]
                        base_mods = self.fid_to_mods[base_fid]
                        # let's check if the modules are the same
                        # in principle we need to make sure that every module the base is compiled in,
                        # is alos on the function's list of modules
                        if 0 != len(set(base_mods).difference(mods)):
                            ext = True
                elif self.cut_off == Generator.CUT_OFF_DIRS:
                    if fid not in self.fid_to_dirs:
                        ext = True
                        # fid will not be in fid_to_dirs if it's an unresolved function (see _get_function_file)
                    else:
                        # internal functions are the ones residing in the specified dirs
                        dirs = self.fid_to_dirs[fid]
                        # it is enough that one of the function's dirs is on the co_dirs list
                        if len(dirs.difference(self.co_dirs)) == len(dirs):
                            ext = True

                elif self.cut_off == Generator.CUT_OFF_FUNCTIONS:
                    # internal functions are the ones with names on the list
                    name = self._get_function_name(fid)
                    if name not in self.co_funcs:
                        ext = True

                elif self.cut_off == Generator.CUT_OFF_FILES:
                    # internal functions are the ones that reside in the
                    # specified source files
                    src, loc, srcs = self._get_function_file(fid)
                    if src not in self.co_files:
                        ext = True

                # if the function is external but we specify --co-dirs, --co-files
                # or --co-funcs, we check if we could pull the function in
                if ext and self.cut_off != Generator.CUT_OFF_DIRS and len(self.co_dirs) > 0:
                    if fid in self.fid_to_dirs:
                        dirs = self.fid_to_dirs[fid]
                        # it is enough that one of the function's dirs is on the co_dirs list
                        if len(dirs.difference(self.co_dirs)) != len(dirs):
                            ext = False

                if ext and self.cut_off != Generator.CUT_OFF_FUNCTIONS and len(self.co_funcs) > 0:
                    # internal functions are the ones with names on the list
                    name = self._get_function_name(fid)
                    if name in self.co_funcs:
                        ext = False

                if ext and self.cut_off != Generator.CUT_OFF_FILES and len(self.co_files) > 0:
                    # internal functions are the ones that reside in the
                    # specified source files
                    src, loc, srcs = self._get_function_file(fid)
                    if src in self.co_files:
                        ext = False

            if ext:
                # logging.debug(
                #    "Function {} is outside of base module {}".format(fid, base_fid))
                external_funcs.add(fid)
            else:
                # logging.debug(
                #    "Function {} is inside of base module {}".format(fid, base_fid))
                tmp_f = self.fnidmap[fid]
                if tmp_f is None:
                    # we've hit an unresolved function or a funcdecl
                    external_funcs.add(fid)
                    continue
                if fid not in internal_funcs:
                    internal_funcs.add(fid)
                    self._get_internal_funcs(
                        tmp_f, internal_funcs, external_funcs)

    # -------------------------------------------------------------------------

    # @base_fids: the ids of the functions we would like to create an off-target for
    # @fids: the ids of all the other functions (that we discovered recursively)
    def _get_function_stats(self, base_fids, fids):
        base_functions = self.fnidmap.get_many(list(base_fids))

        # by default we'll add the dirs in which the base functions reside
        # to the list of allowed funcs
        # by default we'll add the names of the base functions
        # to the list of allowed funcs
        # by default we'll add the files in which base functions are defined
        # to the list of allowed funcs
        for f in base_functions:
            self.co_funcs.add(f["name"])
            src, loc, srcs = self._get_function_file(f["id"])
            dirs = set()
            dirs.add(os.path.dirname(src))
            #self.co_dirs |= dirs
            logging.info(f"co_dirs is {self.co_dirs}")
            #self.co_files.add(src)

        for fid in fids:
            src, loc, srcs = self._get_function_file(fid)

            # Cut-off based on modules
            if (src is None) and (loc is None):
                # that is for the unresolved functions
                mod_paths = ["/tmp/no_such_mod"]
            else:
                #logging.debug(f"function {fid}")                
                mod_paths = self.bassconnector.get_module_for_source_file(
                    src, loc)
            for mod_path in mod_paths:
                if mod_path not in self.modules:
                    if fid in base_fids:
                        self.modules[mod_path] = Module(mod_path, isbase=True)
                    else:
                        self.modules[mod_path] = Module(mod_path, isbase=False)
                self.modules[mod_path].fids.add(fid)
                if fid not in self.fid_to_mods:
                    self.fid_to_mods[fid] = []
                self.fid_to_mods[fid].append(mod_path)
                # else:
                #    logging.error("Ambiguous function to module mapping for fid {}".format(fid))
                #    sys.exit(1)

            # cut-off based on the list of function names
            # we don't really need to collect anything in that case - we will filter out
            # based on names

            # cut-off based on the list of directories
            dirs = set()
            if src is not None:
                dirs.add(os.path.dirname(src))
            else:
                dirs.add("/tmp/no_such_file")
            if len(dirs) != 0:
                if fid not in self.fid_to_dirs:
                    self.fid_to_dirs[fid] = dirs

        self.internal_funcs = set()
        logging.info("Getting internal functions")
        for f in base_functions:
            self._get_internal_funcs(
                f, self.internal_funcs, self.external_funcs)
        external_count = len(fids) - len(self.internal_funcs)
        logging.info("There are {} internal functions {} first external functions and {} external functions".format(
            len(self.internal_funcs), len(self.external_funcs), external_count))

        # please note that the way we get internal/exteral functions is purely based on function calls
        # therefore it is necessary to add any missing functions that might be necessary as a result of
        # pulling in globals (globals could reference functions)

        logging.info("Printing internal functions:")
        for fid in self.internal_funcs:
            f = self.fnidmap[fid]
            logging.info(
                "- [internal] {} @ {}".format(f["name"], f["location"]))

        logging.info("Printing first external functions:")
        for fid in self.external_funcs:
            f = self.fnidmap[fid]
            if f is None:
                # try in funcdecls functions
                f = self.fdmap[fid]
                if f is None:
                    # try in unresolved
                    f = self.umap[fid]
                    logging.info("- [external] {}".format(f["name"]))
                    continue

            if self.func_stats == Generator.FUNC_STATS_DETAILED:
                # let's check how many functions would that function pull in
                query = set()
                query.add(fid)

                if fid in self.stats_cache:
                    query |= self.stats_cache[fid]
                else:
                    self._get_called_functions(query)
                    self.stats_cache[fid] = query
                logging.info("- [external] {} @ {} pulls in another {} functions".format(
                    f["name"], f["location"], len(query) - 1))
            else:
                subtree_count = -1
                if fid in self.stats_cache:
                    # if we are in the basic stats mode, only functions known to not call any other
                    # will be added to stats_cache, which means that the number of called functions is 0
                    subtree_count = 0
                else:
                    tmp = self.fnidmap[fid]
                    if tmp is not None:
                        # let's see if we can tell whether the function doesn't call
                        # any others
                        if "funrefs" not in tmp or len(tmp["funrefs"]) == 0:
                            self.stats_cache[fid] = set([fid])
                            subtree_count = 0
                        else:
                            funcs = set(tmp["funrefs"])
                            self._filter_out_known_functions(funcs, True)
                            self._filter_out_builtin_functions(funcs)
                            if len(funcs) == 0:
                                subtree_count = 0
                            else:
                                found = False
                                for id in funcs:
                                    if id in self.fnidmap:
                                        found = True
                                        # at least one of the called functions is a func
                                        break

                                if not found:
                                    # all of the called functions are either funcdecls or unresolved
                                    # which will be external anyway
                                    subtree_count = 0

                            if subtree_count == 0:
                                self.stats_cache[fid] = set([fid])
                    else:
                        # for funcdecls we wouldn't know how many
                        # other functions they call and also we would never
                        # include them as internal
                        pass
                if subtree_count == -1:
                    logging.info(
                        "- [external] {} @ {}".format(f["name"], f["location"]))
                else:
                    logging.info("- [external] {} @ {} pulls in another {} functions".format(
                        f["name"], f["location"], subtree_count))

    # -------------------------------------------------------------------------

    # from a list of types get all globals referenced in those types

    def _get_globals_from_types(self, types):
        globs = set()
        for t_id in types:
            t = self.typemap[t_id]
            if t is None:
                shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")
                sys.exit(1)
            if "globalrefs" in t:
                logging.debug(
                    "Adding globalrefs found in type {}".format(t["globalrefs"]))
                globs |= set(t["globalrefs"])

        return globs

    # -------------------------------------------------------------------------

    # from a list of globals get all globals referenced in those globals

    def _get_globals_from_globals(self, globals):
        globs = set()
        for g_id in globals:
            g = self.globalsidmap[g_id]
            if "globalrefs" in g:
                logging.debug(
                    "Adding globalrefs found in globals {}".format(g["globalrefs"]))
                globs |= set(g["globalrefs"])

        return globs

    # -------------------------------------------------------------------------

    # from a list of types get all functions referenced in those types
    def _get_funcs_from_types(self, types, skip_list=None):
        funcs = set()
        for t_id in types:
            if skip_list != None and t_id in skip_list:
                continue
            t = self.typemap[t_id]
            if "funrefs" in t:
                logging.debug(
                    "Adding funrefs found in types {}".format(t["funrefs"]))
                funcs |= set(t["funrefs"])

        return funcs

    # -------------------------------------------------------------------------

    # from a list of globals get all functions referenced in those globals
    def _get_funcs_from_globals(self, globals, skip_list=None):
        funcs = set()
        for g_id in globals:
            if skip_list != None and g_id in skip_list:
                continue
            g = self.globalsidmap[g_id]
            if "funrefs" in g:
                logging.debug(
                    "Adding funrefs found in globals {}".format(g["funrefs"]))
                funcs |= set(g["funrefs"])
        return funcs

    # -------------------------------------------------------------------------

    # Walk through pointer or array types and extract underlying record type
    # Returns (RT,TPD) pair where:
    #  RT: underlying record type
    #  TPD: if the underlying record type was a typedef this is the original typedef type
    # In case record type cannot be resolved returns (None,None) pair
    def _resolve_record_type(self,TID,TPD=None):
        
        T = self.typemap[TID]
        if T["class"]=="record" or T["class"]=="record_forward":
            return T,TPD
        elif T["class"]=="pointer" or T["class"]=="const_array" or T["class"]=="incomplete_array":
            TPD = None
            return self._resolve_record_type(T["refs"][0],TPD)
        elif T["class"]=="typedef":
            if TPD is None:
                TPD = T
            return self._resolve_record_type(T["refs"][0],TPD)
        elif T["class"]=="attributed":
            return self._resolve_record_type(T["refs"][0],TPD)
        else:
            return None,None

    # -------------------------------------------------------------------------

    # Get all functions and globals.
    # In C functions can reference other functions and globals and globals can reference other globals and functions.
    # On top of that types can reference functions and globals.
    # In this function we try to discover all the dependencies
    def _discover_functions_and_globals(self, functions, globals, all_types, basedirs, internal_defs=None):
        # get a recursive list of all functions called by our functions of choice
        #logging.info("Getting called functions for {} functions".format(len(functions)))
        logging.info("Initial analysis found {} functions".format(
            len(functions)))

        # find all funrefs among the globals
        logging.info("Getting functions from globals")
        g_types, global_fwd_str, g_str, globals_ids = self._get_global_types(
            functions, [], self.global_types, section_header=False, internal_defs=internal_defs)
        g_funcs = set()
        logging.info("We have {} globals and {} types".format(
            len(globals_ids), len(g_types)))

        # collect all types from functions & globals
        tmp = set()
        types = set()
        types = set(self._get_types_in_funcs(functions, tmp))
        tmp |= internal_defs
        types |= set(g_types)
            
        # types can reference globals too (e.g. via construct like typeof(global_var))
        globals_ids |= self._get_globals_from_types(g_types)
        globals_ids |= self._get_globals_from_types(types)
        globals_ids |= self._get_globals_from_types(tmp)

        # globals can reference other globals, so we have to pull them in
        globals_ids |= set(self._get_recursive_by_id(
            "globals", globals_ids, "globalrefs"))

        # note: we don't need to update global types after recrusively
        # pulling in globals, as the types are already retrieved recursively
        # in _get_global_types
        # TODO: consider typeof and sizeof in global types definitions
        # and initializers
        # TODO: consider if we have all the types from globals: especially
        # the refs from globals pulled in recursively

        # collect functions referenced by globals
        for fid in self._get_funcs_from_globals(globals_ids, globals):
            if fid not in functions:
                g_funcs.add(fid)

        # collect functions referenced by types
        tmp_types = set()
        tmp_types |= types
        tmp_types |= tmp
        for fid in self._get_funcs_from_types(tmp_types, all_types):
            if fid not in functions:
                g_funcs.add(fid)

        globals |= globals_ids

        all_types |= types

        if len(self.internal_funcs) > 0:
            tmp = g_funcs.difference(self.internal_funcs)
            # we are only interested in internal functions
            g_funcs.intersection_update(self.internal_funcs)
            # at the same time, we need to make sure that we update external funcs appropriately
            # that is to add everything that we've found but which was not in the internal functions
            # even though we will not generate the bodies of those functions, we would need to have them
            # beacause they are referenced by globals that we will generate
            self.external_funcs |= tmp

        # let's check if new functions were discovered in globals
        if 0 != len(g_funcs):
            # we've found that globals reference other functions

            logging.info(
                "There are {} additional functions in the global initializers".format(len(g_funcs)))
            to_query = set()
            # we need _some_ function to begin the query; refs will be injected into its funrefs field
            for f in functions:
                if f in self.fnidmap:
                    to_query.add(f)
                    break

            logging.info("get called functions on to_query size of {} and g_funcs size of {}".format(
                len(to_query), len(g_funcs)))
            self._get_called_functions(
                to_query, additional_refs=g_funcs)
            logging.info(
                "We added {} functions as a result of globals analysis".format(len(to_query.difference(functions))))

            # we now have a recursive subtree of functions associated with global
            # in principle we need to repeat the process of globals discovery for them,
            # however we first need to check if the functions are not external as we don't want to
            # repeat the process for functions which we won't generate anyway
            # in other words, we are only interested in getting more data on the functions that
            # are internal and ignore those which we'll generate stubs for
            if len(self.internal_funcs) > 0:
                to_query.intersection_update(self.internal_funcs)
           
            to_query.difference_update(functions)

            if len(to_query) > 0:
                f, g = self._discover_functions_and_globals(
                    to_query, globals, all_types, basedirs, internal_defs)
                if len(self.internal_funcs) > 0:
                    f.intersection_update(self.internal_funcs)
                functions |= f
            functions |= g_funcs
            functions = self._filter_out_known_functions(functions)
            globals |= self._get_globals_from_types(types)

            return functions, globals
        else:
            # that's the easy case - globals were not referencing any new functions,
            # therefore we don't need to recursively call the function again
            logging.info(
                "We have found no further functions as a result of global analysis")

            return functions, globals

    # -------------------------------------------------------------------------

    # Give a type id, return a destination type. It will be tid, except for
    # const_array, incomplete_array and pointer, for which a destination type
    # is returned

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

    def _get_global_decl_types(self, decls, refs, type):
        ret_tids = set()
        for d in decls:
            t_id = refs[d]
            ret_tids.add(self._get_real_type(t_id))

        # now, let's get the true type of the global
        real_tid = self._get_real_type(type)
        return ret_tids, real_tid

    # -------------------------------------------------------------------------

    def _get_file_define(self, fid):
        filename = f"file_{fid}.c"
        define_str = filename.upper()
        define_str = define_str.replace(".", "_")
        define_str = define_str.replace("-", "_")

        return define_str

    # -------------------------------------------------------------------------

    def _find_clashes(self, files, type_clashes, global_clashes, function_clashes, func_glob_clashes):
        for tid_tuple in type_clashes:
            t_id1 = tid_tuple[0]
            t_id2 = tid_tuple[1]

            if t_id1 not in self.type_clash_nums and t_id2 not in self.type_clash_nums:
                self.type_clash_nums[t_id1] = self.type_clash_counter
                self.type_clash_nums[t_id2] = self.type_clash_counter
                self.type_clash_counter += 1
            elif t_id2 not in self.type_clash_nums:
                self.type_clash_nums[t_id2] = self.type_clash_nums[t_id1]
            else:
                self.type_clash_nums[t_id1] = self.type_clash_nums[t_id2]

            # for each t_id find the files it's used in

            tid1_files = set()
            tid2_files = set()

            for fid, file in files.items():
                if t_id1 in file.types:
                    tid1_files.add(fid)
                if t_id2 in file.types:
                    tid2_files.add(fid)

            if tid1_files == tid2_files:
                # both types are used in exactly the same files -> no need to create 
                # header guards
                continue

            if t_id1 not in self.clash_type_to_file:
                self.clash_type_to_file[t_id1] = set()
            self.clash_type_to_file[t_id1] |= tid2_files
            if t_id2 not in self.clash_type_to_file:
                self.clash_type_to_file[t_id2] = set()
            self.clash_type_to_file[t_id2] |= tid1_files


        for gid_tuple in global_clashes:
            g_id1 = gid_tuple[0]
            g_id2 = gid_tuple[1]

            if g_id1 not in self.glob_clash_nums and g_id2 not in self.glob_clash_nums:
                self.glob_clash_nums[g_id1] = self.glob_clash_counter
                self.glob_clash_nums[g_id2] = self.glob_clash_counter
                self.glob_clash_counter += 1
            elif g_id2 not in self.glob_clash_nums:
                self.glob_clash_nums[g_id2] = self.glob_clash_nums[g_id1]
            else:
                self.glob_clash_nums[g_id1] = self.glob_clash_nums[g_id2]

            gid1_files = set()
            gid2_files = set()

            for fid, file in files.items():
                if g_id1 in file.globals:
                    gid1_files.add(fid)
                if g_id2 in file.globals:
                    gid2_files.add(fid)

            if gid1_files == gid2_files:
                # both globals are used in exactly the same files -> no need to create 
                # header guards
                return

            if g_id1 not in self.clash_global_to_file:
                self.clash_global_to_file[g_id1] = set()
            self.clash_global_to_file[g_id1] |= gid2_files
            if g_id2 not in self.clash_global_to_file:
                self.clash_global_to_file[g_id2] = set()
            self.clash_global_to_file[g_id2] |= gid1_files

        for fid_tuple in function_clashes:
            f_id1 = fid_tuple[0]
            f_id2 = fid_tuple[1]

            if f_id1 not in self.func_clash_nums and f_id2 not in self.func_clash_nums:
                self.func_clash_nums[f_id1] = self.func_clash_counter
                self.func_clash_nums[f_id2] = self.func_clash_counter
                self.func_clash_counter += 1
            elif f_id2 not in self.func_clash_nums:
                self.func_clash_nums[f_id2] = self.func_clash_nums[f_id1]
            else:
                self.func_clash_nums[f_id1] = self.func_clash_nums[f_id2]



            fid1_files = set()
            fid2_files = set()

            for fid, file in files.items():
                if f_id1 in file.funcs:
                    fid1_files.add(fid)
                if f_id2 in file.funcs:
                    fid2_files.add(fid)

            if fid1_files == fid2_files:
                # both globals are used in exactly the same files -> no need to create 
                # header guards
                return

            if f_id1 not in self.clash_global_to_file:
                self.clash_function_to_file[f_id1] = set()
            self.clash_function_to_file[f_id1] |= fid2_files
            if f_id2 not in self.clash_function_to_file:
                self.clash_function_to_file[f_id2] = set()
            self.clash_function_to_file[f_id2] |= fid1_files

        for tuple in func_glob_clashes:
            f_id = tuple[0]
            g_id = tuple[1]

            if f_id not in self.func_clash_nums:
                self.func_clash_nums[f_id] = self.func_clash_counter
                self.func_clash_counter += 1                
            if g_id not in self.glob_clash_nums:
                self.glob_clash_nums[g_id] = self.glob_clash_counter
                self.glob_clash_counter += 1


            fid_files = set()
            gid_files = set()

            for fid, file in files.items():
                if f_id in file.funcs:
                    fid_files.add(f_id)
                if g_id in files.globals:
                    gid_files.add(g_id)
            
            if fid_files == gid_files:
                return

            if f_id not in self.clash_function_to_file:
                self.clash_function_to_file[f_id] = set()
            self.clash_function_to_file[f_id] |= gid_files
            if g_id not in self.clash_global_to_file:
                self.clash_global_to_file[g_id] = set()
            self.clash_global_to_file[g_id] = fid_files

    # -------------------------------------------------------------------------

    def _getAttrNum(self,RT):
        if "attrnum" in RT:
            return RT["attrnum"]
        else:
            return 0

    # Checks if a given type (depT) depends on the record type RT
    def _isAnonRecordDependent(self,RT,depT):
        if RT["id"]==depT["id"]:
            return True
        elif (depT["class"]=="const_array" or depT["class"]=="incomplete_array") and depT["refs"][0]==RT["id"]:
            # struct { u16 index; u16 dist;} near[0];
            return True
        else:
            return False

    def _generate_verification_recipes(self):
        verify_recipes = list()
        verify_recipes.append("    /* Here comes autogenerated recipes to verify AoT record types structure layout. Modify at your own peril! */")
        verify_recipes.append("    /* --- Number of generated structs: %d */\n"%(len(self.struct_types)))
        # RT is the record type we are verifying (it can be record or typedef)
        # if RT is originally typedef then TPD will point to the typedef type and RT will collapse to the underlying record type
        # MT is a type of a corresponding member of RT
        # if MT is originally typedef then MTPD will point to the typedef type and MT will collapse to the underlying record type
        for RT in self.struct_types:
            TPD = None
            if RT["class"]=="typedef":
                TPD = RT
                if TPD["name"] in Generator.VERIFY_STRUCT_TYPE_LAYOUT_BLACKLIST:
                    continue
                RT = self._get_typedef_dst(RT)
            if RT["str"]!="" or TPD:
                member_tuples = list()
                if RT["size"]>0:
                    try:
                        # As of the current quirk of dbjson when there's anonymous record inside a structure followed by a name we will have two entries in "refs"
                        #  but only single entry in "memberoffsets"
                        #   struct X { ... };       // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
                        #   struct X { ... } w;     // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
                        #   struct { ... };         // "__!anonrecord__" as a normal member (present in decls)
                        #   struct { ... } w;       // ignore "__!anonrecord__" from refs/refnames/usedrefs (present in decls)
                        #  summary: ignore all "__!recorddecl__" from decls and "__!anonrecord__" if there's the same refs entry that follows
                        real_refs = list()
                        ignore_count=0
                        bitfield_members = set([])
                        if "bitfields" in RT:
                            bitfield_members = set([int(x) for x in RT["bitfields"].keys()])
                        for i in range(len(RT["refnames"])-self._getAttrNum(RT)):
                            if i in RT["decls"] and ( RT["refnames"][i]!="__!anonrecord__" or (i+1<len(RT["refs"]) and 
                                    self._isAnonRecordDependent(self.typemap[RT["refs"][i]],self.typemap[RT["refs"][i+1]]))):
                                ignore_count+=1
                                continue
                            else:
                                real_refs.append( (RT["refs"][i],RT["refnames"][i],RT["memberoffsets"][i-ignore_count],[],[],i in bitfield_members) )
                    except Exception as e:
                        sys.stderr.write(json.dumps(RT,indent=4)+"\n")
                        raise e
                    while len(real_refs)>0:
                        ref,name,offset,memberoffset_list,refname_prefix_list,is_bitfield = real_refs.pop(0)
                        MT = self.typemap[ref]
                        if MT["class"]=="typedef":
                            MTPD = MT
                            MT = self._get_typedef_dst(MT)
                        if MT["class"]=="record":
                            if MT["size"]>0:
                                internal_real_refs = list()
                                ignore_count=0
                                bitfield_members = set([])
                                if "bitfields" in MT:
                                    bitfield_members = set([int(x) for x in MT["bitfields"].keys()])
                                for i in range(len(MT["refnames"])-self._getAttrNum(MT)):
                                    if i in MT["decls"] and ( MT["refnames"][i]!="__!anonrecord__" or (i+1<len(MT["refs"]) and 
                                            self._isAnonRecordDependent(self.typemap[MT["refs"][i]],self.typemap[MT["refs"][i+1]]))):
                                        ignore_count+=1
                                        continue
                                    else:
                                        member_list = list()
                                        if name!="__!anonrecord__":
                                            member_list.append(name)
                                        internal_real_refs.append( (MT["refs"][i],MT["refnames"][i],MT["memberoffsets"][i-ignore_count],
                                            memberoffset_list+[offset],refname_prefix_list+member_list,i in bitfield_members) )
                                real_refs = internal_real_refs+real_refs
                        else:
                            member_name = ".".join(refname_prefix_list+[name])
                            member_offset = sum(memberoffset_list+[offset])
                            member_tuples.append((member_name,member_offset,is_bitfield))
                verify_member_recipes = list()
                for name,offset,is_bitfield in member_tuples:
                    if not is_bitfield:
                        verify_member_recipes.append("        VERIFY_OFFSET(%s,%d);"%(name,offset/8))
                    else:
                        verify_member_recipes.append("        /* Ignore verification of bitfield %s */"%(name))
                if TPD:
                    verify_recipes.append(Generator.VERIFY_STRUCT_TYPE_TEMPLATE%(TPD["name"],RT["size"]/8,"\n".join(verify_member_recipes)))
                elif RT["union"] is False:
                    verify_recipes.append(Generator.VERIFY_STRUCT_TEMPLATE%(RT["str"],RT["size"]/8,"\n".join(verify_member_recipes)))
                else:
                    verify_recipes.append(Generator.VERIFY_UNION_TEMPLATE%(RT["str"],RT["size"]/8,"\n".join(verify_member_recipes)))
        return verify_recipes

    # -------------------------------------------------------------------------

    def capture_literals(self, global_ids, function_ids):
        
        for g_id in global_ids:
            g = self.globalsidmap[g_id]
            if "literals" in g:
                literals = g["literals"]
                self.literals[Generator.INT_LITERAL] |= set(literals[Generator.INT_LITERAL])
                self.literals[Generator.FLOAT_LITERAL] |= set(literals[Generator.FLOAT_LITERAL])
                self.literals[Generator.CHAR_LITERAL] |= set(literals[Generator.CHAR_LITERAL])
                self.literals[Generator.STRING_LITERAL] |= set(literals[Generator.STRING_LITERAL])

        for f_id in function_ids:
            f = self.fnidmap[f_id]
            if f and "literals" in f:
                literals = f["literals"]
                self.literals[Generator.INT_LITERAL] |= set(literals[Generator.INT_LITERAL])
                self.literals[Generator.FLOAT_LITERAL] |= set(literals[Generator.FLOAT_LITERAL])
                self.literals[Generator.CHAR_LITERAL] |= set(literals[Generator.CHAR_LITERAL])
                self.literals[Generator.STRING_LITERAL] |= set(literals[Generator.STRING_LITERAL])

            # in addition to literals, we are going to extract constatnt values from switch info
            if f and "switches" in f:
                for s in f["switches"]:
                    for c in s["cases"]:
                        # the int value can be found at c[0]
                        try:
                            self.literals[Generator.INT_LITERAL].add(int(c[0]))
                        except Exception:
                            logging.error(f"Switch error detected in function {f['name']}")
                        if len(c) == 8:
                            # we have the range-based case - the next value is at c[4]
                            try:
                                self.literals[Generator.INT_LITERAL].add(int(c[4]))
                            except Exception:
                                logging.error(f"Switch error detected in function {f['name']}")
 
        # finally, we can generate a dictionary file with literals        
        with open(f"{self.out_dir}/{Generator.AOT_LITERALS_FILE}", "w") as f:
            i = 0
            _str = ""
            for l in self.literals[Generator.INT_LITERAL]:
                # thanks to https://stackoverflow.com/questions/30285849/pythonic-way-to-convert-an-integer-into-a-hex-escaped-string
                # https://stackoverflow.com/questions/5864271/reverse-a-string-in-python-two-characters-at-a-time-network-byte-order
                # https://stackoverflow.com/questions/7822956/how-to-convert-negative-integer-value-to-hex-in-python
                if l < 0:
                    hex_str = hex(l & (2**64 - 1)) 
                else:
                    hex_str = format(l, '#02x')
                if len(hex_str) % 2:
                    hex_str = hex_str.replace("0x", "0x0")
                hex_str = hex_str.replace("0x", "")
                # reverse bytes for little-endian
                hex_str = "".join(reversed([ hex_str[j:j+2] for j in range(0, len(hex_str), 2) ]))
                hex_str = re.sub("(..)", r"\\x\1", hex_str)
                if len(hex_str) == 0:
                    continue
                _str += f"literal{i}=\"{hex_str}\"\n"
                i += 1
            for l in self.literals[Generator.FLOAT_LITERAL]:
                # thanks to https://stackoverflow.com/questions/23624212/how-to-convert-a-float-into-hex/38879403
                hex_str = hex(struct.unpack('<Q', struct.pack('<d', l))[0])
                hex_str = hex_str.replace("L", "")
                if len(hex_str) % 2:
                    hex_str = hex_str.replace("0x", "0x0")
                hex_str = hex_str.replace("0x", "")
                # reverse bytes for little-endian
                hex_str = "".join(reversed([ hex_str[j:j+2] for j in range(0, len(hex_str), 2) ]))
                hex_str = re.sub("(..)", r"\\x\1", hex_str)                
                if len(hex_str) == 0:
                    continue
                _str += f"literal{i}=\"{hex_str}\"\n"
                i += 1
            for l in self.literals[Generator.CHAR_LITERAL]:
                if len(str(l)) == 0:
                    continue
                _str += f"literal{i}=\"{str(l)}\"\n"
                i += 1
            for l in self.literals[Generator.STRING_LITERAL]:
                if len(str(l)) <= Generator.MAX_STRING_LITERAL_LEN and len(str(l)) > 0:
                    raw = repr(l)[1:-1]
                    if "%" not in raw:
                        raw = raw.replace("\\", "\\\\")
                        _str += f"literal{i}=\"" + raw + "\"\n"
                        i += 1
            f.write(_str)

    # -------------------------------------------------------------------------

    # @depth: if 0, considers only functions from the same directory as
    #         the function of interest, if 1 consider also functions
    #         from 1 dir up, etc.

    def generate_off_target(self, function_names, depth=0):
        # use type and function information
        # to generate off-target source code

        all_funcs_with_asm_copy = self.all_funcs_with_asm
        self.all_funcs_with_asm = set()

        function_ids = []

        # let's check if the user provided function ids instead of names
        for i in range(len(function_names)):
            if function_names[i].isdigit():
                f_id = int(function_names[i])
                func = self.fnidmap[f_id]
                f = func['name']
                if not self.include_asm and self._func_contains_assembly(func):
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
                    if not p.startswith('/') and p.count('/') != 0 and self.source_root is not None:
                        p = self.source_root + "/" + p
                    locations[f[0]].append(os.path.abspath(p))
                    locations[f[0]].append(f[1])
                else:
                    locations[f[0]] = []

            function_ids = []
            for f, loc in locations.items():
                if f not in self.fnmap:
                    logging.error("Function {} not found!".format(f))
                    with open(self.out_dir + "/" + f + "_error.txt", "w") as file:
                        file.write(f"Unable to find function {f}\n")
                    return False
                cnt = self.fnmap.get_count(f)
                if cnt != 1:
                    logging.warning(
                        "Expected 1 occurrence of function {}, found {}.".format(f, cnt))
                    # try to narrow down the search
                    files = locations[f]
                    tmp = self.fnmap.get_many([f])
                    success = False
                    before = len(function_ids)
                    locs = set()
                    for func in tmp:
                        fid = func["id"]
                        src, loc, srcs = self._get_function_file(fid)
                        locs.add(loc)
                        #filename = os.path.basename(src)
                        filename = src
                        logging.info(
                            "Searched file {}, function file {}".format(files, filename))
                        subpath = False
                        for path in files:
                            if path in filename:
                                    subpath = True
                        if subpath is True or filename in files or os.path.basename(src) in files:
                            if not self.include_asm and self._func_contains_assembly(func):
                                logging.error(
                                    f"Cannot generate off-target for {f} as it contains an inline assembly")
                                continue
                            function_ids.append(fid)
                            success = True
                            logging.info(
                                "Successfully located function {} (id: {}) in file {}".format(f, fid, loc))
                    after = len(function_ids)
                    if ((after - before) > 1):
                        logging.warn("We still have more than one function candidate")
                        success = False

                    if success == False:
                        logging.error(("Unable to uniquely locate function {}. " +
                                    "Please try the following notation: function_name@file_name").format(f))
                        logging.error(f"Possible locations for function {f} are: {locs}")
                        with open(self.out_dir + "/" + f + "_error.txt", "w") as file:
                            file.write(f"Unable to uniquely locate function {f}\n")

                        return False
                else:
                    func = self.fnmap[f]
                    if not self.include_asm and self._func_contains_assembly(func):
                        logging.error(
                            f"Cannot generate off-target for {f} as it contains an inline assembly")
                        with open(self.out_dir + "/" + func["name"] + "_error.txt", "w") as file:
                            file.write(
                                "Cannot generate off-target due to inline assembly\n")
                        continue
                    function_ids.append(func["id"])

        if 0 == len(function_ids):
            logging.error("No functions to generate")
            #shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")
            #sys.exit(0)
            return False

        # first we need to gather the required data
        # we start with getting all the functions called by our function of interest

        # get the base directories - that is based on the location of the
        # functions of interest
        basedirs = set()
        for f in function_ids:
            self.functions.add(f)
            src, loc, srcs = self._get_function_file(f)

            dir = os.path.dirname(src)

            for i in range(depth):
                dir = os.path.dirname(dir)
            logging.info("adding basedir {}".format(dir))
            basedirs.add(dir)

        self.globals = set()
        self._get_called_functions(self.functions)
        # TODO: filter out external functions -> consider adding a filter to the
        # get_called_functions method (this might cover the globals too)

        # TODO2: when do we need to call get_function_stats?
        # do we need to call it with self.functions as the second arg?
        # what would be the best way to create a filter for internal/external

        all_types = set()
        internal_defs = set()
        self._discover_functions_and_globals(
            self.functions, self.globals, all_types, basedirs, internal_defs)
        self.all_funcs_with_asm = all_funcs_with_asm_copy


        logging.debug("funcs are " + str(self.functions))
        self._get_function_stats(function_ids, self.functions)
        # after calling get_function_stats the list of external funcs can be found in
        # self.external_funcs and the list of internal funcs can be found in self.internal_funcs

        logging.info("Generator found " +
                     str(len(self.functions)) + " functions")


        if self.cut_off != Generator.CUT_OFF_NONE:
            # TODO: now I'm going to repeat some steps from above, but the filtering could be
            # done in a more efficient way

            # if self.func_stats == Generator.FUNC_STATS_DETAILED and self.external_inclusion_margin > 0:
            if self.external_inclusion_margin > 0:
                # let's see which of the external functions could be included
                included = set()
                new_external = set()
                for f_id in self.external_funcs:
                    if f_id in self.stats_cache:
                        # please note that self.stats_cache will be filled if we executed
                        # _get_function_stats (partially for basic stats, full for detailed)
                        # if the id is found in cache we will immediately know how many functions does
                        # the function pull in
                        # -1 as the function is included there as well
                        count = len(self.stats_cache[f_id]) - 1
                        if count < self.external_inclusion_margin:
                            # external function pulls in no more than a threshold of other functions
                            # let's make them all internal then
                            _included = set(self.stats_cache[f_id])
                            if not self.include_asm:
                                _included = set([id for id in _included if id not in self.all_funcs_with_asm])
                            
                            self.internal_funcs |= _included
                            included |= _included
                            # stats_cache only takes into account functions and not funcdecls
                            # since we include a function / list of functions we need to check if
                            # some of the funcdecls they call might need to be added to external
                            # funcs
                            for f in _included:
                                func = self.fnidmap[f]
                                for ref in func["funrefs"]:
                                    if ref in self.fdmap or ref in self.umap:
                                        # found a reference that is either func decl or unresolved
                                        new_external.add(ref)

                self.external_funcs.difference_update(included)
                self.external_funcs |= new_external
                logging.info(f"Included {len(included)} functions")
                logging.info(
                    f"Now we have {len(self.internal_funcs)} internal and {len(self.external_funcs)} external")

            # TODO: for now I will also filter out as external all the functions with inline assembly
            # perhaps in the future there is a better way to handle those
            #removed = set()
            for f_id in self.internal_funcs:
                f = self.fnidmap[f_id]
                if f is not None:
                    if not self.include_asm and self._func_contains_assembly(f):
                        self.external_funcs.add(f_id)
                        logging.info(
                            f'Function {f["name"]} contains inline assembly - will treat it as external')
            self.globals = set()
            self.internal_defs = set()
            for f in function_ids:
                self.functions.add(f)

            # we have to add the main functions we focus on
            for f in function_ids:
                self.internal_funcs.add(f)

            # just in case: filter out known functions
            self.internal_funcs = self._filter_out_known_functions(
                self.internal_funcs, True)
            self.external_funcs = self._filter_out_known_functions(
                self.external_funcs, True)

            # at this point we alredy know which functions are internal and which are external;
            # however, we don't know which globals should be pulled in by the internal functions -> that is what
            # we're going to learn next

            # let's operate on a copy of internal_funcs, just in case
            internals = set(self.internal_funcs)
            all_types = set()
            self._discover_functions_and_globals(
                internals, self.globals, all_types, basedirs, internal_defs)
            logging.info(
                f"functions size is {len(self.functions)}, external functions size is {len(self.external_funcs)} internal funcs size is {len(self.internal_funcs)} known funcs size is {len(self.known_funcs_ids)}")

            # if len(internals) != len(self.internal_funcs):

            # sys.exit(1)
        else:
            # we don't need to to cut off any functions
            # TODO: currently the list of internal/external is established in the _get_function_stats function
            # and only based on the module -> that needs to be parametrized
            self.internal_funcs = self.functions
            self.external_funcs = set()

        
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

        for func in self.internal_funcs:
            function = self.fnidmap[func]
            if None == function:
                logging.warning("Function {} not found. Trying funcdecl.")
                # TODO: handle funcdelcs
                function = self.fdmap[func]
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
        for func in self.external_funcs:
            function = self.fnidmap[func]
            if None == function:
                logging.warning("Function {} not found. Trying funcdecl.")
                # TODO: handle funcdelcs
                function = self.fdmap[func]
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
            g = self.globalsidmap[glob]

            # loc_index = g["location"].find(":")
            # loc = g["location"][:loc_index]
            # logging.info("loc is {}".format(loc))
            fid = g["fid"]
            logging.debug("fid is {}".format(fid))
            if fid not in files:
                files[fid] = File()
                files_for_globals += 1
            files[fid].globals.append(glob)

        # static inline functions are knonw to cause troubles
        # one of them is the case when multiple versions of the same function
        # exsit, the only difference being compile_time assert macro in the body
        copy = self.static_and_inline_funcs.copy()
        decls = set()
        for func in copy:
            f = self.fnidmap[func]
            if f is not None:
                decl = f["declbody"]
            if decl not in decls:
                decls.add(decl)
            else:
                logging.info(
                    f"removing a duplicate of an inline static function {f['name']}")
                del self.static_and_inline_funcs[func]

        # once we have all the files
        # handle static and inline functions
        for func in self.static_and_inline_funcs:
            additional = set()
            f = self.fnidmap[func]
            if f is not None:
                f_id = f["id"]
                if f_id in self.static_funcs_map:
                    additional = self.static_funcs_map[f_id]
            fids = set(self.static_and_inline_funcs[func])

            prev = len(fids)
            fids |= additional
            if prev != len(fids):
                logging.info("workardound working: we have more fids now")

            for fid in fids:
                if fid in files and func not in files[fid].funcs:
                    logging.info("Adding func {} to file {}".format(func, fid))
                    files[fid].funcs.append(func)

        for f_id in self.internal_funcs:
            if f_id in self.known_funcs_ids:
                self.known_funcs_present.add(self._get_function_name(f_id))
        for f_id in self.external_funcs:
            if f_id in self.known_funcs_ids:
                self.known_funcs_present.add(self._get_function_name(f_id))
        for f_id in self.static_and_inline_funcs:
            if f_id in self.known_funcs_ids:
                self.known_funcs_present.add(self._get_function_name(f_id))
        self.adjust_funcs_lib()
 

        logging.info("We have {} distinct files".format(len(files)))

        # once we know all the internal functions, let's gather some info on pointer sizes
        _funcs = set()
        _funcs |= self.internal_funcs    
        _funcs |= set(self.static_and_inline_funcs.keys())
        _funcs.difference_update(self.external_funcs)
        _funcs = self._filter_out_known_functions(_funcs)
        _funcs = self._filter_out_builtin_functions(_funcs)
        _types = set()
        _types |= all_types
        _types |= internal_defs
        _internal_defs = set()

        _t, _d = self._get_types_recursive(_types, internal_defs=_internal_defs)
        _types |= set(_t)
        _types |= _internal_defs
        _funcs = self.fnidmap.get_many(_funcs)
        _types = self._remove_duplicated_types(_types)
        _types = self.typemap.get_many(_types)        
        self._generate_member_size_info(_funcs, _types)
        #self._print_member_size_info()
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
        self.static_inline_headers = {}
        for f_id in set(self.static_and_inline_funcs.keys()):
            f = self.fnidmap[f_id]

            if f is not None and "inline" in f and f["inline"]:
                filename = self._create_static_inline_header(f)
                logging.info(f"Created static / inline header {filename}")

        all_global_ids = set()
        self.fid_to_filename = {}
        for fid, file in files.items():
            logging.info("Generating file {} of {}".format(i, fileno))
            i += 1
            funcs = file.funcs
            globs = file.globals

            for id in self.static_inline_headers:
                if id in funcs:
                    funcs.remove(id)

            if len(funcs) == 0 and len(globs) == 0:
                logging.info("This file is empty: skipping")
                continue
            logging.info(f"funcs number {len(funcs)} globs number {len(globs)}, funcs are {funcs}")
            filename = ""
            # generate source file
            if fid in static_files:
                str_header, str_file, filename, func_ids, globals_ids, types, internal_defs = self._create_src_file(
                    fid, funcs, globs, includes, static_files[fid].funcs)
                all_global_ids |= globals_ids
                self.fid_to_filename[fid] = filename
                self.sources_to_types[filename] = types
                self.file_contents[filename] = str_file
                static_files[fid].types = types
                static_files[fid].filename = filename
                static_files[fid].globals = globals_ids
                static_files[fid].funcs = func_ids
            else:
                str_header, str_file, filename, func_ids, globals_ids, types, internal_defs = self._create_src_file(
                    fid, funcs, globs, includes, [])
                all_global_ids |= globals_ids
                self.fid_to_filename[fid] = filename
                self.sources_to_types[filename] = types
                self.file_contents[filename] = str_file
                files[fid].types = types
                files[fid].filename = filename
                files[fid].globals = globals_ids
                files[fid].funcs = func_ids
            sources.append(filename)

        self.external_funcs = self._filter_out_builtin_functions(
            self.external_funcs)
        for fid, file in stub_files.items():
            funcs_copy = file.funcs.copy()
            for f_id in file.funcs:
                if f_id in self.static_inline_headers:
                    funcs_copy.remove(f_id)
            if len(funcs_copy) == 0:
                logging.info("This stub file is empty: skipping")
                continue
            str_header, str_file, filename, func_ids, globals_ids, types, internal_defs = self._create_src_file(
                f'{fid}', funcs_copy, [], [], [], stubs=True)
            self.sources_to_types[filename] = types
            self.file_contents[filename] = str_file
            all_global_ids |= globals_ids
            sources.append(filename)
            stub_files[fid].types = types
            stub_files[fid].filename = filename
            stub_files[fid].globals = globals_ids
            stub_files[fid].funcs = func_ids

        if "main" not in function_names:
            # if "main" is not among the functions of interest
            # we need to generate it ourselves
            # TODO: always generate test driver - it will be necessary to
            # introduce instrumentation
            sources.append("aot.c")

            # we will need to generate all type, function and global data which is necessary

            str_header, str_file, filename, globals_ids, types, internal_defs = self._create_test_driver(
                function_ids, static_functions, all_global_ids)
            self.sources_to_types[filename] = types
            self.file_contents[filename] = str_file

            # generate data init for the static globals
            known_type_names = set()
            for t_id in types:
                t = self.typemap[t_id]
                if t["class"] == "record":                
                    known_type_names.add(t["str"])

            logging.info(f"known type names are {known_type_names}")
            new_types = set()
            _str = ""
            contents_to_change = {}
            filename_to_fpointer_stubs = {}
            for g_id in all_global_ids:                
                self.fpointer_stubs = []
                g = self.globalsidmap[g_id]
                if self.dump_global_hashes:
                    self.global_hashes.append(str(g["hash"]))
                glob_has_init = g['hasinit']
                # one more check: sometimes globals are pointers initialized to null
                g_tid = g["type"]
                g_t = self.typemap[g_tid]
                g_t = self._get_typedef_dst(g_t)                        
                if g_t["class"] == "pointer":
                    initstr = g["init"]
                    if initstr == "((void *)0)":
                        glob_has_init = False 

                if not glob_has_init and g["linkage"] == "internal":
                    # get id of the global definition file
                    g_fid = g["fid"]
                    filename = self.fid_to_filename[g_fid]

                    pointers = []
                    self.recursion_fuse = 0
                    init_obj = None
                    if self.init:
                        param_tid, init_obj = self.globs_init_data[g['id']]

                    tmp_str, alloc = self._generate_var_init(
                        g["name"], self.typemap[g["type"]], "", pointers, known_type_names=known_type_names, new_types=new_types, 
                        entity_name=g['name'], fuse=0, init_obj=init_obj)
                    if filename not in contents_to_change:
                        contents_to_change[filename] = ""
                    contents_to_change[filename] += tmp_str

                    if len(self.fpointer_stubs):
                        if filename not in filename_to_fpointer_stubs:
                            filename_to_fpointer_stubs[filename] = []
                        for stub in self.fpointer_stubs:
                            filename_to_fpointer_stubs[filename].append(stub)

            for filename in contents_to_change:
                contents = self.file_contents[filename]
                _str = contents_to_change[filename]
                if len(_str) > 0:
                    _str = _str.replace("\n", "\n\t");
                    contents = contents.replace(Generator.AOT_STATIC_GLOBS_MARKER, _str);
                    if filename in filename_to_fpointer_stubs:
                        _str = ""
                        stubs = filename_to_fpointer_stubs[filename]
                        for stub in stubs:
                            _str += f"{stub}\n\n"
                        contents = contents.replace(Generator.AOT_STATIC_GLOBS_FPTRS, _str)
                    self.file_contents[filename] = contents


            self.capture_literals(all_global_ids, self.internal_funcs)

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
        for t_id in self.all_types:
            if t_id in tclashes:
                continue
            
            t = self.typemap[t_id]
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
            for t_id2 in self.all_types:
                if t_id == t_id2:
                    continue
                
                t2 = self.typemap[t_id2]
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
                    if t_id in self.dup_types and t_id2 in self.dup_types[t_id]:
                        continue
     
                    if cl2 == "record_forward": 
                        # no need to ifdef record fwd
                        continue 
                    
                    if cl == "typedef": 
                        if t["refs"][0] == t_id2:
                            continue
                        if t_id2 in self.dup_types and t["refs"][0] in self.dup_types[t_id2]:
                            continue
                    if cl2 == "typedef":
                        if t2["refs"][0] == t_id:
                            continue
                        if t_id in self.dup_types and t2["refs"][0] in self.dup_types[t_id]:
                            continue

                    # we've found a name clash right here
                    type_clashes.add((t_id2, t_id))
                    tclashes.add(t_id)
                    tclashes.add(t_id2)
                    logging.debug(f"adding types to clash: {t_id2}, {t_id}")                
        logging.info(f"We've found {len(type_clashes)} clashing types: {type_clashes}")

        logging.info("Looking for global name clashes")
        global_clashes = set()
        global_names = set()
        name_to_gids = {}
        gclashes = set()
        for g_id in all_global_ids:
            if g_id in gclashes:
                continue

            name = self.globalsidmap[g_id]["name"]
            if len(name) == 0:
                continue

            global_names.add(name)
            if name not in name_to_gids:
                name_to_gids[name] = []
            name_to_gids[name].append(g_id)

            for g_id2 in all_global_ids:
                if g_id == g_id2:
                    continue
                name2 = self.globalsidmap[g_id2]["name"]
                if name == name2:
                    # we've found a name clash right here
                    global_clashes.add((g_id2, g_id))
                    gclashes.add(g_id)
                    gclashes.add(g_id2)
        logging.info(f"We've found {len(global_clashes)} clashing globals")

        logging.info("Looking for function name clashes")
        function_clashes = set()
        func_names = set()
        name_to_fids = {}
        fclashes = set()
        for f_id in self.all_funcs:
            if f_id in fclashes:
                continue

            if f_id in self.fnidmap:
                name = self.fnidmap[f_id]["name"]
            elif f_id in self.fdmap:
                name = self.fdmap[f_id]["name"]
            else:
                name = self.umap[f_id]["name"]

            if len(name) == 0:
                continue

            func_names.add(name)
            if name not in name_to_fids:
                name_to_fids[name] = []
            name_to_fids[name].append(f_id)

            for f_id2 in self.all_funcs:
                if f_id == f_id2:
                    continue

                if f_id2 in self.fnidmap:
                    name2 = self.fnidmap[f_id2]["name"]
                elif f_id2 in self.fdmap:
                    name2 = self.fdmap[f_id2]["name"]
                else:
                    name2 = self.umap[f_id2]["name"]
                if name == name2:
                    # we've found a name clash right here
                    function_clashes.add((f_id2, f_id))
                    fclashes.add(f_id)
                    fclashes.add(f_id2)
        logging.info(f"We've found {len(function_clashes)} clashing functions: {function_clashes}")


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
        self.clash_type_to_file = {}
        self.clash_global_to_file = {}
        self.clash_function_to_file = {}

        logging.info("find clashes in files")
        self._find_clashes(files, type_clashes,
                           global_clashes, function_clashes, func_glob_clashes)
        logging.info("find clashes in static files")
        self._find_clashes(static_files, type_clashes,
                           global_clashes, function_clashes, func_glob_clashes)
        logging.info("find clashes in stub files")
        self._find_clashes(stub_files, type_clashes,
                           global_clashes, function_clashes, func_glob_clashes)

        logging.info(f"Clash data: type to file {len(self.clash_type_to_file)} items, global to file {len(self.clash_global_to_file)} items, func to file {len(self.clash_function_to_file)} items")

        self.all_funcs |= set(self.static_and_inline_funcs.keys())

        self.include_std_headers = [ f"<{h}>" for h in self.include_std_headers ]
        str_header, str_file, filename, func_ids, globals_ids, types, internal_defs = self._create_src_file(
            Generator.AOT_HEADER_ID, self.all_funcs, all_global_ids, [], static_functions, create_header=True)

        str_header += "\n#endif"
        self._store_item_in_header(Generator.AOT_HEADER, str_header)

        # we take the Makefile from resources directory

        # store file contents to disk
        for filename in self.file_contents:
            contents = self.file_contents[filename]

            with open(f"{self.out_dir}/{filename}", "a+") as file:
                file.write(contents)

        # try to pretty-print the files
        clang_format = shutil.which("clang-format")
        if clang_format is not None:
            logging.info("Will format files with clang-format")
            to_format = [ 'aot.c' ]
            for filename in to_format:                
                subprocess.run(["clang-format", "-i", f"{self.out_dir}/{filename}"])

        logging.info("Output generated in " + self.out_dir)
        logging.info(f"AOT_OUT_DIR: {os.path.abspath(self.out_dir)}\n")
        if self.init and self.dump_smart_init:
            types = self.typemap.get_many(self.all_types)
            #out_name = "smart_init.json"
            #logging.info(f"As requested, dumping the smart init data to a JSON file {out_name}")
            for t in types:
                entry, single_init, offset_types = self._get_cast_ptr_data(t)
                if entry is not None or offset_types is not None:
                    logging.info(f"Data init for type {t['id']}: {entry}, {offset_types}")
                for i in range(len(t['refs'])):
    #                   if t['usedrefs'][i] != -1:
                    entry, single_init, offset_types = self._get_cast_ptr_data(t, i)
                    if entry is not None or offset_types is not None:
                        logging.info(f"Data init for type {t['id']}, member {i}: {entry}, {offset_types}")

        tmp = "\n#### STATS ####\n"
        tmp += "Files count: AOT_FILES_COUNT: {}\n".format(len(self.stats))
        self.all_types = self._remove_duplicated_types(self.all_types)

        tmp += "Types count: AOT_TYPES_COUNT: {}\n".format(len(self.all_types))
        struct_types = 0
        t_no_dups = self.typemap.get_many(self.all_types)
        for t in t_no_dups:
            if t["class"] == "record":
                struct_types += 1
                
        tmp += "Struct types count: AOT_STRUCT_TYPES_COUNT: {}\n".format(struct_types)
        tmp += "Globals count: AOT_GLOBALS_COUNT: {}\n".format(len(all_global_ids))

        self.internal_funcs.difference_update(self.external_funcs)
        self.internal_funcs = self._filter_out_known_functions(self.internal_funcs)
        self.internal_funcs = self._filter_out_builtin_functions(self.internal_funcs)
        self.external_funcs = self._filter_out_known_functions(self.external_funcs)
        self.external_funcs = self._filter_out_builtin_functions(self.external_funcs)
        tmp += "Funcs count: AOT_INT_FUNCS_COUNT: {}\n".format(len(self.internal_funcs))
        tmp += "Funcs count: AOT_EXT_FUNCS_COUNT: {}\n".format(len(self.external_funcs))
        logging.info("{}".format(tmp))
        if len(self.funcs_with_asm) > 0:
            tmp = "\n# WARNING: the functions below have inline assembly commented out:\n"
            for fid, data in self.funcs_with_asm.items():
                f = self.fnidmap[fid]
                file = data["file"]
                diff = data["diff"]
                tmp += f'[{file}] : {f["name"]}\n'

        logging.info("{}".format(tmp))
        logging.info(
            f"functions size is {len(self.functions)}, external functiosn size is {len(self.external_funcs)} internal funcs size is {len(self.internal_funcs)}")
        # logging.info("all funcs")
        # for f in self.all_funcs:
        #    logging.info(self._get_function_name(f))
        # logging.info("external funcs")
        # for f in self.external_funcs:
        #    logging.info(self._get_function_name(f))
        # logging.info("internal funcs")
        # for f in self.internal_funcs:
        #    logging.info(self._get_function_name(f))
        # logging.info("functions")
        # for f in self.functions:
        #     logging.info(f"{self._get_function_name(f)}")

        logging.info(
            f"genrated functions {self.generated_functions}, generated stubs {self.generated_stubs}")
        logging.info(
            f"generated {files_for_globals} files for globals and {len(self.globals)} globals")
        logging.info(
            f"Stubs returning a pointer are mapped to the following return addresses:")
        for s in self.stub_to_return_ptr:
            if self.include_asm or s not in self.stubs_with_asm:
                # by a 'bucket' we mean the range within which the stub-generated value falls
                bucket = (self.stub_to_return_ptr[s] - Generator.AOT_SPECIAL_PTR) // Generator.AOT_SPECIAL_PTR_SEPARATOR // 2
                logging.info(f"AOT_STUB_MAPPING{bucket}:{s}:{hex(self.stub_to_return_ptr[s] - Generator.AOT_SPECIAL_PTR_SEPARATOR)}:{hex(self.stub_to_return_ptr[s] + Generator.AOT_SPECIAL_PTR_SEPARATOR)}")

        if self.verify_struct_layout:
            logging.info(
                f"Generating code to verify layout of generated struct types in {self.out_dir}/{Generator.VERIFY_STRUCT_LAYOUT_SOURCE}")
            verify_recipes = self._generate_verification_recipes()
            with open(os.path.join(self.out_dir,Generator.VERIFY_STRUCT_LAYOUT_TEMPLATE),"rt") as f:
                template_out = f.read()
            with open(os.path.join(self.out_dir,Generator.VERIFY_STRUCT_LAYOUT_SOURCE),"wt") as f:
                f.write(template_out%("\n".join(verify_recipes)))

        if self.dump_global_hashes:
            logging.info(
                f"Saving hashes of global variables used into {self.out_dir}/{Generator.GLOBAL_HASH_FILE}")
            with open(f"{self.out_dir}/{Generator.GLOBAL_HASH_FILE}", "w") as file:
                file.write("\n".join(self.global_hashes))

        if self.dynamic_init:
            logging.info(
                f"Creating files required for dynamic initialization")
            # copy the predefined files required for dynamic initialization
            predefined_files_dyn_init = ["dyn_init.c", "dyn_init.h"]
            res_dir = f"{os.path.abspath(os.path.dirname(sys.argv[0]))}/resources/"
            for f in predefined_files_dyn_init:
                shutil.copyfile(f"{res_dir}/{f}", f"{self.out_dir}/{f}")
                shutil.copymode(f"{res_dir}/{f}", f"{self.out_dir}/{f}")
            
            with open(os.path.join(res_dir,Generator.FUNCTION_POINTER_STUB_FILE_TEMPLATE),"rt") as f:
                fptrstub_out = f.read()
            with open(os.path.join(self.out_dir,Generator.FUNCTION_POINTER_STUB_FILE_SOURCE),"wt") as f:
                fstub_decls_out = "\n".join(["extern int (*%s)(void);"%(fstub) for fstub,fstub_id in self.function_pointer_stubs])
                fstubs_out = "\n".join(["  { \"%s\", 0 },"%(fstub) for fstub,fstub_id in self.function_pointer_stubs])
                fstubs_init = "\n".join(["  fptrstub_pair_array[%d].address = %s;"%(i,fstubT[0]) for i,fstubT in enumerate(self.function_pointer_stubs)])
                flib_stubs = "\n".join(["%s"%(flibstub) for flibstub,flibstub_id in self.lib_function_pointer_stubs])
                fstubs_init_call = "\n".join(["  init_%s();"%(x) for x in self.global_trigger_name_list-self.global_trigger_name_list_exclude])
                f.write(fptrstub_out%(fstub_decls_out,len(self.function_pointer_stubs),fstubs_out,fstubs_init,fstubs_init_call,flib_stubs))
            
            with open(os.path.join(res_dir,Generator.FUNCTION_POINTER_KNOWN_FUNCS_STUB_FILE_TEMPLATE),"rt") as f:
                fptrstub_known_funcs_out = f.read()
            with open(os.path.join(self.out_dir,Generator.FUNCTION_POINTER_KNOWN_FUNCS_STUB_FILE_SOURCE),"wt") as f:
                known_funcs_decls = list()
                known_funcs_stub_list = list()
                used_fstubs = set([fstub_id for fstub,fstub_id in self.function_pointer_stubs])
                used_lib_fstubs = set([fstub_id for fstub,fstub_id in self.lib_function_pointer_stubs])
                for f_id in self.known_funcs_ids:
                    function = self.fnidmap[f_id]
                    if function and function["linkage"]!="internal" and function["id"] in used_fstubs and function["id"] not in used_lib_fstubs:
                        known_funcs_stub_list.append(self._get_function_pointer_stub(function))
                        known_funcs_decls.append(function["declbody"]+";")
                f.write(fptrstub_known_funcs_out%("\n".join(known_funcs_decls),"\n".join(known_funcs_stub_list)))
        
        return True

    # -------------------------------------------------------------------------

    # Using variable type data and name, generate variable definition
    def _generate_var_def(self, type, name):
        str = ""
        cl = type["class"]

        if cl == "builtin":
            str += type["str"] + " " + name
        elif cl == "typedef":
            str += type["name"] + " " + name
        elif cl == "record" or cl == "record_forward":
            if not type["union"]:
                str += "struct {}".format(type["str"]) + " " + name
            else:
                str += "union {}".format(type["str"]) + " " + name
        elif cl == "enum":
            str += "enum {}".format(type["str"]) + " " + name
        elif cl == "function":
            str += type["def"].replace(" (", " ({})(".format(name))
        elif cl == "incomplete_array":
            # since it's impossible to just declare incomplete array
            # without initialization we have to create a pointer
            dst_type = self.typemap[type["refs"][0]]
            name = "* {}".format(name)
            str += self._generate_var_def(dst_type, name)
        elif cl == "const_array":
            dst_type = self.typemap[type["refs"][0]]
            dst_size = dst_type["size"]
            if dst_size != 0:
                const_size = int(type["size"] / dst_size)
            else:
                const_size = 0
            name = "{}[{}]".format(name, const_size)
            str += self._generate_var_def(dst_type, name)
        elif cl == "pointer":
            dst_type = self.typemap[type["refs"][0]]
            name = "* {}".format(name)
            str += self._generate_var_def(dst_type, name)
        else:
            logging.error(
                "Unable to generate var def {} for class {}".format(name, cl))
            shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")
            sys.exit(1)
        if str[-1] != ";":
            str += ";"
        return str

    # -------------------------------------------------------------------------

    # To fuzz or not to fuzz, that is the question!
    # This function decides this the same way Hamlet would do:
    # - if it's a builtin type -> we fuzz it
    # - otherwise -> don't fuzz it
    def _to_fuzz_or_not_to_fuzz(self, t):

        cl = t["class"]

        if cl == "builtin" or cl == "enum":
            return True
        elif cl == "const_array" or cl == "incomplete_array":
            dst_type = self.typemap[t["refs"][0]]
            dst_type = self._get_typedef_dst(dst_type)
            return self._to_fuzz_or_not_to_fuzz(dst_type)

        return False

    # -------------------------------------------------------------------------

    def _get_typename_from_type(self, type):
        typename = self._generate_var_def(type, "!tmp")
        typename = typename.replace("!tmp", "")
        # remove the trailing semicolon
        typename = typename[:-1]
        typename = typename.strip()
        return typename

    # -------------------------------------------------------------------------

    def _get_cast_ptr_data(self, type, member_number=CAST_PTR_NO_MEMBER):
        type_to_check = None
        if member_number == Generator.CAST_PTR_NO_MEMBER:
            type_to_check = type
        else:
            # it's a structured type
            type_to_check = self.typemap[type['refs'][member_number]]

        #if not self._is_void_ptr(type_to_check):
        #    return None, False

        t_id = type["id"]    
        _t_id = self._get_real_type(t_id)    
        _type = self.typemap[_t_id]
        logging.debug(f"Getting casted data for {self._get_typename_from_type(type)}")
        if _type["class"] == "record":
            # if the type is a record, we keep the cast data under the type, not it's 
            # pointer, so we need to get the pointer destination first
            t_id = _t_id
            type = _type

        entry = None
        single_init = False

        if t_id in self.casted_pointers:
            entry = self.casted_pointers[t_id]
            if entry is None:
                logging.info(f"Entry is null for type {t_id}")
            if member_number in entry:
                if len(entry[member_number]) == 1:
                    # we've detected that there is only one cast for this structure and member
                    single_init = True
            else:
                logging.debug(f"Member {member_number} not found for entry for type {t_id}")
                entry = None
        else:
            typename = self._get_typename_from_type(type)
            logging.debug(f"No cast information found for type {typename}")


        if entry is not None and member_number != Generator.CAST_PTR_NO_MEMBER:
            logging.debug(
                f"Member {type['refnames'][member_number]} found in the void pointers map: {entry}, t_id: {t_id}")
        elif entry is not None:
            logging.debug(
                f"Type {t_id} found in the void pointers map")
        else:
            logging.debug(f"Type {type['id']} found in the void pointers map ")
        
        offset_types = None
        if t_id in self.offset_pointers:
            offset_types = self.offset_pointers[t_id]
        return entry, single_init, offset_types

    # -------------------------------------------------------------------------

    def _get_const_array_size(self, type):
        if type["class"] == "incomplete_array" and type["size"] == 0:
            return 0

        elem_type = type["refs"][0]
        elem_size = self.typemap[elem_type]["size"]
        if elem_size != 0:
            return type["size"] // elem_size
        else:
            return 0
        
    # -------------------------------------------------------------------------

    def _get_tagged_var_name(self):
        self.tagged_vars_count += 1
        return f"\"aot_var_{self.tagged_vars_count}\""

    # -------------------------------------------------------------------------

    # Given variable name and type, generate correct variable initialization code.
    # For example:
    # name = var, type = struct A*
    # code: struct A* var = (struct A*)malloc(sizeof(struct A*));
    def _generate_var_init(self, name, type, res_var, pointers, level=0, skip_init=False, known_type_names=None, cast_str=None, new_types=None,
                           entity_name=None, init_obj=None, fuse=None, fid=None, count=None):
        # in case of typedefs we need to get the first non-typedef type as a point of
        # reference

        if fuse is not None:
            fuse += 1
            if fuse > Generator.MAX_RECURSION_DEPTH:
                logging.error("Max recursion depth reached")
                with open(self.out_dir + "/aot_recursion_error.txt", "w") as file:
                    file.write(f"Max recursion depth reached while generating var init\n")
                shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")

                sys.exit(1)

        if False == self.init:
            return "", False

        type = self._get_typedef_dst(type)

        cl = type["class"]
        if self.debug_vars_init:
            logging.info(f"generating var init for {name} cl {cl} type {type['id']}")

        t_id = type["id"]
     
        if t_id in self.used_types_data:
            type = self.used_types_data[t_id]
            if self.debug_vars_init:
                logging.info(f"used type found for {t_id}. Type id is {type['id']}")
        str = ""
        # if level == 0 and skip_init == False:
        #     str = "{} = ".format(res_var)
        # else:
        #     str = ""

        # Init types based on type class:
        # 1) builtin:
        # memset based on sizeof
        # 2) typedef:
        # memset based on sizeof
        # 3) struct:
        # memset based on sizeof
        # 4) enum:
        # we could initialize just to the first member or use a generic
        # init with constraints on the value
        # 5) function pointer
        # We could generate a function with a matching signature
        # and assign the pointer to that function.
        # Alternatively we could also just do a memset
        # 6) incomplete_array
        # That would be something like, e.g. char* argv[]
        # We probably need to have a param that controls how many elements
        # to create. Once we know that, we initialize like for const_array.
        # 7) const_array
        # That would be something like, e.g. char* argv[10]
        # We need to create a loop, inside of which we generate
        # initializer for each member
        # 8) pointer
        # memset based on sizeof

        # The right memory init is hard to get. As long as we have non-pointer types
        # it's moderately easy: just allocate a block of memory and assign selected data
        # to it. However, once we operate on pointer, it is very hard to
        # know if a pointer is just a single object or a group of objects.
        # If it's a single object we could just allocate another one and again populate
        # it with data. If it's an array or a void pointer, it might be very hard to tell.
        # The only way to tell is by executing the code and detecting usage patterns.
        # Luckily, e.g. in the kernel code it should be moderately easy to tell - copy_from_user
        # would only perform a shallow copy of pointers - if no further copy is performed,
        # it's already an indication of something being wrong. On the other hand, another
        # call to copy_from_user on a pointer member should indicate the size and type of
        # memory pointed to by the pointer.

        # we need to override copy_from user and simiar methods and dynamically allocate
        # memory on request
        alloc = False
        is_array = False
        loop_count = 0
        name_change = False

        dst_type = type

        typename = self._get_typename_from_type(type)


        if init_obj is not None and init_obj.t_id != dst_type["id"] and type["class"] == "record_forward":
            # see if we might be dealing with record_forward of the same record
            _tmp_id = init_obj.t_id
            _dst_tid = dst_type['id']
            if init_obj.is_pointer:
                _tmp_id = self._get_real_type(_tmp_id)
                _dst_tid = self._get_real_type(_dst_tid)
            init_type = self.typemap[_tmp_id]
            _dst_type = self.typemap[_dst_tid]
            if init_type["class"] == "record" and _dst_type["class"] == "record_forward" and init_type["str"] == _dst_type["str"]:
                if self.debug_vars_init:
                    logging.info(f"Updating dst_type from record_fwd {dst_type['id']} to record {init_obj.t_id}")
                type = self.typemap[init_obj.t_id]
                dst_type = type
                cl = type["class"]
                t_id = type["id"]

        if "pointer" == cl or "const_array" == cl or "incomplete_array" == cl:

            # let's find out the last component of the name
            index_dot = name.rfind(".")
            index_arrow = name.rfind("->")
            index = -1
            if index_dot > index_arrow:
                index = index_dot
            else:
                index = index_arrow

            pointer = False
            member_name = name
            name_base = ""
            if index != -1:
                name_base = name[:index]
                if index == index_dot:
                    index += 1
                else:
                    index += 2
                    pointer = True
                member_name = name[index:]                            

            if "const_array" == cl:
                dst_type = type["refs"][0]
                dst_size = self.typemap[dst_type]["size"] // 8
                if dst_size != 0:
                    array_count = (type["size"] // 8) // dst_size
                else:
                    array_count = 0
                sizestr = "[{}]".format(array_count)
                typename = typename.replace(sizestr, "")
                typename = typename.strip()

                # if level == 0 or skip_init == False:
                #     str += "aot_memory_init_ptr(&{}, sizeof({}), {});\n".format(name,
                #                                                               typename, array_count)
                #     alloc = True
                is_array = True
                loop_count = array_count
                if 0 == loop_count:
                    if self.debug_vars_init:
                        logging.warn("special case: adding a single member to a const array")
                    loop_count = 1 # this is a special corner case -> we already allocated memory for 1 member
                    str += "// increasing the loop count to 1 for a const array of size 0\n"
            elif "incomplete_array" == cl and type['size'] == 0:
                is_array = True
                loop_count = 0
                if self.debug_vars_init:
                    logging.warn("special case: adding a single member to a const array")
                loop_count = 1 # this is a special corner case -> we already allocated memory for 1 member
                str += "// increasing the loop count to 1 for a const array of size 0\n"
            else:
                dst_type = self._get_typedef_dst(self.typemap[type["refs"][0]])
                # special case among pointers are function pointers
                if "pointer" == cl:
                    # assuming pointer has a single ref - the destination type
                    dst_cl = dst_type["class"]
                
                
                    # # let's find out the last component of the name
                    # index_dot = name.rfind(".")
                    # index_arrow = name.rfind("->")
                    # index = -1
                    # if index_dot > index_arrow:
                    #     index = index_dot
                    # else:
                    #     index = index_arrow

                    # pointer = False
                    # member_name = ""
                    # name_base = ""
                    # if index != -1:
                    #     name_base = name[:index]
                    #     if index == index_dot:
                    #         index += 1
                    #     else:
                    #         index += 2
                    #         pointer = True
                    #     member_name = name[index:]                            
            
                    if "function" == dst_cl:
                        stub_name = name.replace(".", "_")
                        stub_name = stub_name.replace("->", "_")
                        stub_name = stub_name.replace("[", "_")
                        stub_name = stub_name.replace("]", "")
                        stub_name = stub_name.replace("(", "")
                        stub_name = stub_name.replace(")", "")
                        stub_name = stub_name.replace("*", "")
                        stub_name = stub_name.strip()
                        stub_name = f"aotstub_{stub_name.split()[-1]}"
                        
                        tmp_str, fname = self._generate_function_stub(dst_type["id"], stubs_file=False,
                                                                      fpointer_stub=True, stub_name=stub_name)

                        str = f"aot_memory_init_func_ptr(&{name}, {fname});\n"
                        #str = f"{name} = {fname};\n"
                        if tmp_str not in self.fpointer_stubs:
                            self.fpointer_stubs.append(tmp_str)
                        return str, alloc
                    elif (dst_type["id"] in pointers and (pointers.count(dst_type["id"]) > 1 or member_name in ["prev", "next"]) or
                            (member_name in ["pprev"] and self._get_real_type(dst_type["id"]) in pointers)):
                        # we have already initialized the structure the pointer points to
                        # so we have to break the loop
                        if self.debug_vars_init:
                            logging.info(f"breaking linked list for {name}")
                        str += f"/* note: {name} pointer is already initialized (or we don't want a recursive init loop) */\n"
                        if member_name in ["prev", "next"]:                                
                            if pointer:
                                str += f"aot_memory_setptr(&{name},{name_base});\n"
                            else:
                                str += f"aot_memory_setptr(&{name},&{name_base});\n"
                        elif member_name in ["pprev"]:
                            if pointer:
                                str += f"aot_memory_setptr(&{name},&{name_base});\n"
                            else:
                                str += f"aot_memory_setptr(&{name},&{name_base}.next);\n"

                        return str, alloc
                    elif known_type_names != None and dst_type["class"] == "record_forward" and dst_type["str"] not in known_type_names:     
                        recfwd_found = False
                        if init_obj is not None and init_obj.t_id != dst_type["id"]:
                            # see if we might be dealing with record_forward of the same record
                            _tmp_id = init_obj.t_id
                            if init_obj.is_pointer:
                                _tmp_id = self._get_real_type(_tmp_id)
                            init_type = self.typemap[_tmp_id]
                            if init_type["class"] == "record" and dst_type["class"] == "record_forward" and init_type["str"] == dst_type["str"]:
                                if self.debug_vars_init:
                                    logging.info(f"Detected that we are dealing with a pointer to record forward but we know the real record")
                                recfwd_found = True
                        if not recfwd_found:
                            str += f"/*{name} left uninitialized as it's not used */\n"
                            if self.debug_vars_init:
                                logging.info(f"/*{name} left uninitialized as it's not used */\n")
                            return str, False
                    
                    # pointers are allocated as arrays of size >= 1
                    is_array = True

                    if dst_cl == "pointer" or dst_cl == "const_array":
                        name_change = True
                elif "incomplete_array" == cl:
                    is_array = True

                if count is None:
                    loop_count = self.ptr_init_size
                else:
                    loop_count = count
                
                null_terminate = False
                user_init = False
                user_fuzz = None
                tag = False
                value = None
                min_value = None
                max_value = None
                if level == 0 and self.init_data is not None and entity_name in self.init_data:
                    if self.debug_vars_init:
                        logging.info(f"Detected that {entity_name} has user-provided init")
                    item = self.init_data[entity_name]
                    for entry in item["items"]:
                        entry_type = "unknown"
                        if "type" in entry:
                            entry_type = entry["type"]
                            if " *" not in entry_type:
                                entry_type = entry_type.replace("*", " *")
                  
                        if name in entry["name"] or entry_type == self._get_typename_from_type(type):
                            if self.debug_vars_init:
                                logging.info(f"In {entity_name} we detected that item {name} of type {entry_type} has a user-specified init")
                            
                            if "size" in entry:
                                loop_count = entry["size"]
                                if "size_dep" in entry:
                                    # check if the dependent param is present (for functions only)
                                    dep_id = entry["size_dep"]["id"]
                                    dep_add = entry["size_dep"]["add"]
                                    dep_names = []
                                    dep_user_name = ""
                                    dep_found = False
                                    for i in item["items"]:
                                        if i["id"] == dep_id:
                                            dep_names = i["name"]
                                            if "user_name" in i:
                                                dep_user_name = i["user_name"]
                                            else:
                                                logging.error("user_name not in data spec and size_dep used")
                                                sys.exit(1) 
                                            dep_found = True
                                            break
                                    if dep_found and fid:
                                        f = self.fnidmap[fid]                                        
                                        if f is not None and len(dep_names) > 0:
                                            for index in range(1, len(f["types"])):
                                                if "name" in f["locals"][index - 1] and f["locals"][index - 1]["parm"]:
                                                    param_name = f["locals"][index - 1]["name"]
                                                    if param_name in dep_names:
                                                        loop_count = dep_user_name
                                                        if dep_add != 0:
                                                            loop_count = f"{loop_count} + {dep_add}" 

                            if "nullterminated" in entry:
                                if entry["nullterminated"] == "True":
                                    null_terminate = True
                            if "tagged" in entry:
                                if entry["tagged"] == "True":
                                    tag = True
                            if "value" in entry:
                                value = entry["value"]
                            if "min_value" in entry:
                                min_value = entry["min_value"]
                            if "max_value" in entry:
                                max_value = entry["max_value"]
                            if "fuzz" in entry:
                                if entry["fuzz"] is True:
                                    user_fuzz = 1
                                else:
                                    user_fuzz = 0
                                
                            user_init = True
                            break # no need to look further
                
                if user_init:
                    entry = None
                    single_init = False
                else:
                    entry, single_init, offset_types = self._get_cast_ptr_data(type)
                    if self.debug_vars_init:
                        logging.info(f"it's a pointer init obj {init_obj} offset types {offset_types} type {type['id']}") 
                    
                    final_objs = []
                    if offset_types is not None and init_obj is not None:
                        if self.debug_vars_init:
                            logging.info(f"init_obj is {init_obj}")
                        to_process = []
                        to_keep = []
                        if self.debug_vars_init:
                            logging.info(f"this init_obj has {len(init_obj.offsetof_types)} offsetof_types") 
                        for types, members, obj in init_obj.offsetof_types:
                            to_keep = [] # indices to remove
                            for i in range(len(offset_types)):
                                _types, _members = offset_types[i]
                                if _types == types and _members == members:
                                    to_keep.append(i)  
                                    to_process.append((types, members, obj))                                    
                                    break
                        tmp = []
                        if len(to_keep) < len(offset_types):
                            if self.debug_vars_init:
                                logging.info(f"We reduced offset_types by using derefs trace info")
                                logging.info(f"Before it was {len(offset_types)} now it is {len(to_keep)}")
                            for i in to_keep:
                                tmp.append(offset_types[i])
                            offset_types = tmp
                        # at this point, we should be left with only those offsetof derefs that 
                        # are found in the derefs trace
                        # there is still a possibility that further offsetof uses were applied 
                        # to the already offset types -> let's find out all of the potential outcomes
                        final = []
                        while (len(to_process) > 0):
                            types, members, obj = to_process.pop()
                            if len(obj.offsetof_types) == 0:
                                # if there is an unlikely sequence of offsetof operators we are interested
                                # in the last one in the trace applied only
                                final.append((types, members))
                                final_objs.append(obj)
                                if self.debug_vars_init:
                                    logging.info("No more offset types, the object is final")
                            else:
                                for _types, _members, _obj in obj.offsetof_types:
                                    to_process.append((_types, _members, _obj))
                        if len(final) > 0:
                            if self.debug_vars_init:
                                logging.info("updating offset types")
                            offset_types = final

                    if offset_types is not None and (0 == len(offset_types)):
                        offset_types = None

                if not user_init and offset_types is not None: # and level == 0
                    str_tmp = ""
                    # this type has been used to pull in its containing type
                    str_tmp += "\n// smart init : we detected that the type is used in the offsetof operator"

                    # we will have to emit a fresh variable for the containing type
                    variant = ""
                    variant_num = 1
                    i = 0
                    for i in range(len(offset_types)):

                        types, members = offset_types[i]
                        _dst_t = self.typemap[types[0]] # the destination type of offsetof goes first
                        typename = self._get_typename_from_type(_dst_t)
                        _dst_tid = _dst_t["id"]
                        if new_types != None:
                            new_types.add(_dst_tid)
                        fuzz = int(self._to_fuzz_or_not_to_fuzz(_dst_t))
                        name_tmp = name.replace(typename, "")
                        name_tmp = name_tmp.replace(".", "_")
                        name_tmp = name_tmp.replace("->", "_")
                        name_tmp = name_tmp.replace("[", "_")
                        name_tmp = name_tmp.replace("]", "_")
                        name_tmp = name_tmp.replace(" ", "")
                        name_tmp = name_tmp.replace("(", "")
                        name_tmp = name_tmp.replace(")", "")
                        name_tmp = name_tmp.replace("*", "")
                        fresh_var_name = f"{name_tmp}_offset_{i}"
                        is_vla_struct = False
                        extra_padding = 0
                        if _dst_t["class"] == "record":
                            last_tid = _dst_t["refs"][-1]
                            last_type = self.typemap[last_tid]
                            if last_type["class"] == "const_array" or (last_type["class"] == "incomplete_array" and last_type["size"] == 0): 
                                array_count = self._get_const_array_size(last_type)
                                if 0 == array_count:
                                    # a special case of variable lenght array as the last member of a struct
                                    is_vla_struct = True
                                    last_type_name = self._get_typename_from_type(last_type).replace("[0]", "")                                     
                                    extra_padding = f"sizeof({last_type_name})"

                        if not is_vla_struct: 
                            str_tmp += f"\n{typename} {fresh_var_name};"
                        else:
                            str_tmp += f"\n// making extra space for the variable lenght array at the end of the struct"
                            str_tmp += f"\n{typename}* {fresh_var_name} = malloc(sizeof({typename}) + {extra_padding});"
                            fresh_var_name = f"(*{fresh_var_name})"
                        
                        if self.debug_vars_init:                            
                            logging.info(f"typename is {typename} name_tmp is {name_tmp} fresh_var_name is {fresh_var_name}")
                        comment = ""
                        if len(offset_types) > 1:
                            comment = "//"
                            variant = f"variant {variant_num}"
                            variant_num += 1
                        str_tmp += "\n{} // smart init {}\n".format(
                            comment, variant)
                        # str += "{} aot_memory_init_ptr(&{}, sizeof({}), {} /* count */, {} /* fuzz */);\n".format(
                        #     comment, name, typename, self.ptr_init_size, fuzz)
                        #pointers.append(dst_t["id"])
                         
                        obj = None
                        if i < len(final_objs):
                            obj = final_objs[i]
                        elif init_obj is not None:
                            if self.debug_vars_init:
                                logging.info(f"not enough objects in final_objs: len is {len(final_objs)}, init_obj: {init_obj} ")
                            shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")

                            sys.exit(1)
                        if obj == init_obj:
                            if self.debug_vars_init:
                                logging.info(f"Object is the same {obj}")
                            #sys.exit(1) 
                        else:
                            if self.debug_vars_init:
                                logging.info(f"Object is different obj is {obj}")

                        # we have to assign our top-level 
                        # parameter to the right member of the containing type
                        member_name = ""
                        for i in range(len(members)):
                            member_no = members[i]
                            _tmp_t = self.typemap[types[i]]
                            deref = ""
                            
                            _tmp_name = _tmp_t['refnames'][member_no]
                            if _tmp_name == "__!anonrecord__" or _tmp_name == "__!recorddecl__" or _tmp_name == "__!anonenum__":
                                continue

                            if len(member_name) > 0:                                
                                if _tmp_t["class"] == "pointer":
                                    deref = "->"
                                else:
                                    deref = "."
                            member_name += f"{deref}{_tmp_name}"

                        str_tmp += f"{name} = &{fresh_var_name}.{member_name};\n"

                        if self.debug_vars_init:
                            logging.info("variant c") 
                        _str_tmp, alloc_tmp = self._generate_var_init(fresh_var_name, 
                                                                    _dst_t,
                                                                    res_var,
                                                                    pointers[:],
                                                                    level,
                                                                    skip_init,
                                                                    known_type_names=known_type_names,
                                                                    cast_str=None,
                                                                    new_types=new_types,
                                                                    init_obj=obj,
                                                                    fuse=fuse)
                        str_tmp += _str_tmp                        
                        i += 1

                        if len(offset_types) > 1 and variant_num > 2:
                            str_tmp = str_tmp.replace("\n", "\n//")
                            if str_tmp.endswith("//"):
                                str_tmp = str_tmp[:-2]

                        str += str_tmp
                        alloc = False

                    #if len(offset_types) == 1:
                    if self.debug_vars_init:
                        logging.info("Returning after detecting offsetof")
                    #logging.info(f"str is {str}, offset_types len is {len(offset_types)}, str_tmp is {str_tmp}")
                    return str, alloc
                else: # todo: consider supporting offsetof + cast at level 0

                    force_ptr_init = False
                    if not user_init and entry is not None and init_obj is not None:
                        if self.debug_vars_init:
                            logging.info(f"this is not user init, entry is {entry}") 
                        # entry is not None, which means we have some casts
                        # let's check if we have some additional hints in our init object
                        # we keed all casts history in the cast_types array, but the 
                        # latest type is always stored in the t_id/original_tid
                        latest_tid = init_obj.original_tid
                        if latest_tid in entry[Generator.CAST_PTR_NO_MEMBER]:
                            if self.debug_vars_init:
                                logging.info(f"Current object's tid {latest_tid} detected in entry - will use that one")
                            entry = copy.deepcopy(entry)
                            entry[Generator.CAST_PTR_NO_MEMBER] = [ latest_tid ]
                            single_init = True
                        else:
                            if self.debug_vars_init:
                                logging.info(f"current tid {latest_tid} not found in entry")

                        
                        skipped_count = 0
                        for _tid in entry[Generator.CAST_PTR_NO_MEMBER]:
                            active_type = self.typemap[self._get_real_type(t_id)]
                            active_type = self._get_typedef_dst(active_type)                                    
                            casted_type = self.typemap[self._get_real_type(_tid)]
                            casted_type = self._get_typedef_dst(casted_type)
                            struct_types = [ "record", "record_forward" ]
                            if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                skipped_count += 1

                        if not skip_init and skipped_count == len(entry[Generator.CAST_PTR_NO_MEMBER]):
                            # we have to do it since there will be no init in the other case
                            force_ptr_init = True

                    if not single_init or force_ptr_init:
                        typename = typename.replace("*", "", 1)
                        typename = typename.strip()
                        if user_fuzz is None:
                            fuzz = int(self._to_fuzz_or_not_to_fuzz(dst_type))
                        else:
                            fuzz = user_fuzz

                        extra_padding = None
                        # test for a corner case: a struct with the last member being a const array of size 0
                        if dst_type["class"] == "record" and len(dst_type["refs"]) > 0:
                            last_tid = dst_type["refs"][-1]
                            last_type = self.typemap[last_tid]
                            if last_type["class"] == "const_array" or (last_type["class"] == "incomplete_array" and last_type["size"] == 0): 
                                array_count = self._get_const_array_size(last_type)
                                if 0 == array_count:
                                    # corner case detected -> it means that we have to add allocate some special room
                                    # to accommodate for that 
                                    last_type_name = self._get_typename_from_type(last_type).replace("[0]", "")                                     
                                    extra_padding = f"sizeof({last_type_name})"
                                    logging.warning(f"Our current item {name} of type {typename} has a zero-sized array")

                        # check all the types the object was casted to and select the size which
                        # fits the largest of those types
                        multiplier = None
                        
                        names = set()
                        if init_obj is not None and not user_init:
                            if len(init_obj.cast_types) > 0:                                
                                max = dst_type["size"]                                
                                for _obj_tid, _obj_orig_tid, _is_ptr in init_obj.cast_types:                                    
                                    final_tid = _obj_orig_tid
                                    if  _is_ptr:
                                        final_tid = self._get_real_type(final_tid)                                    
                                    final_type = self.typemap[final_tid]
                                    names.add(self._get_typename_from_type(final_type))
                                    
                                    final_type = self._get_typedef_dst(final_type)
                                    if final_type["size"] > max:
                                        max = final_type["size"]
                                if max > dst_type["size"]:
                                    if dst_type["size"] == 0:
                                        if max % 8 == 0:
                                            multiplier = f"{max // 8}"
                                        else:
                                            multiplier = f"{max // 8} + 1"
                                    else:
                                        multiplier = (max // dst_type["size"]) + 1
                                        multiplier = f"sizeof({typename})*{multiplier}"
                                    if extra_padding:
                                        multiplier = f"{multiplier} + {extra_padding}"
                                        str += f"// smart init: allocating extra space for a 0-size const array member\n"
                                    str += f"// smart init: this object has many casts: using larger count to accommodate the biggest casted type\n"
                                    str += f"// the other types are: {names}\n"
                       
                        addsize = 0
                        if not user_init and typename == "char" and fuzz != 0 and not null_terminate:
                            # we have a var of type char* and we want to fuzz it 
                            # in this case we allocate more bytes and 0-terminate just in case
                            addsize = 32
                        elif not user_init and typename == "void" and fuzz != 0 and not null_terminate:
                            # we have a var of type void* and we want to fuzz it 
                            # in this case we allocate more bytes and 0-terminate just in case
                            addsize = 128
    
                        cnt = loop_count    
                        if count is None and addsize != 0:
                            cnt = loop_count + addsize

                        tagged_var_name = 0
                        if tag:
                            tagged_var_name = self._get_tagged_var_name()
                        if multiplier is None:
                            if extra_padding is None:
                                str += "aot_memory_init_ptr(&{}, sizeof({}), {} /* count */, {} /* fuzz */, {});\n".format(
                                    name, typename, cnt, fuzz, tagged_var_name)
                            else:
                                # a rather rare case of extra padding being non-zero
                                str += f"// smart init: allocating extra space for a 0-size const array member\n"
                                str += "aot_memory_init_ptr(&{}, sizeof({}) + {}, {} /* count */, {} /* fuzz */, {});\n".format(
                                    name, typename, extra_padding, cnt, fuzz, tagged_var_name)
                        else:
                            str += "aot_memory_init_ptr(&{}, {}, {} /* count */, {} /* fuzz */, {});\n".format(                                
                                name, multiplier, cnt, fuzz, tagged_var_name)
                        if addsize and not null_terminate:                                                                                    
                            # use intermediate var to get around const pointers
                            str += f"tmpname = {name};\n"
                            str += f"tmpname[{cnt} - 1] = '\\0';\n"


                        if null_terminate:
                            str += f"{name}[{loop_count} - 1] = 0;\n"

                        if value is not None:
                            str += f"#ifdef KLEE\n"
                            str += "if (AOT_argc == 1) {\n"
                            str += f"    klee_assume({name} == {value});\n"
                            str += f"    klee_skip_tag();\n"
                            str += "}\n"
                            str += f"#endif\n"
                        if min_value is not None:
                            str += f"if ({name} < {min_value}) {name} = {min_value};\n"
                        if max_value is not None:
                            str += f"if ({name} > {max_value}) {name} = {max_value};\n"
                        if tag:
                            str += f"aot_tag_memory({name}, sizeof({typename}) * {cnt}, 0);\n" 

                    if not skip_init and entry is not None:
                        # we are dealing with a pointer for which we have found a cast in the code

                        variant = ""
                        variant_num = 1
                        cast_done = False
                        for _dst_tid in entry[Generator.CAST_PTR_NO_MEMBER]:
                            _dst_t = self.typemap[_dst_tid]
                            typename = self._get_typename_from_type(_dst_t)
                             
                            active_type = self.typemap[self._get_real_type(t_id)]
                            active_type = self._get_typedef_dst(active_type)                                    
                            casted_type = self.typemap[self._get_real_type(_dst_tid)]
                            casted_type = self._get_typedef_dst(casted_type)
                            struct_types = [ "record", "record_forward" ]
                            if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                if self.debug_vars_init:
                                    logging.info("will not consider cast of structural type to non-structural type")
                                continue

                            if new_types != None:
                                new_types.add(_dst_tid)
                            fuzz = int(self._to_fuzz_or_not_to_fuzz(_dst_t))

                            comment = ""
                            # str += "{} aot_memory_init_ptr(&{}, sizeof({}), {} /* count */, {} /* fuzz */);\n".format(
                            #     comment, name, typename, self.ptr_init_size, fuzz)
                            #pointers.append(dst_t["id"])
                            if self.debug_vars_init:
                                logging.info("variant d")
                            cast_done = True
                            str_tmp, alloc_tmp = self._generate_var_init(name, 
                                                                        _dst_t,
                                                                        res_var,
                                                                        pointers[:],
                                                                        level,
                                                                        skip_init,
                                                                        known_type_names=known_type_names,
                                                                        cast_str=typename,
                                                                        new_types=new_types,
                                                                        init_obj=init_obj,
                                                                        fuse=fuse)
                            if not single_init:
                                comment = "//"
                                variant = f"variant {variant_num}"
                                variant_num += 1
                            str_tmp = "\n{} // smart init (a) {}: we've found that this pointer var is casted to another type: {}\n{}".format(
                                comment, variant, typename, str_tmp)
                            #logging.info(str_tmp)
                            if not single_init:
                                str_tmp = str_tmp.replace(
                                    "\n", "\n//")
                                if str_tmp.endswith("//"):
                                    str_tmp = str_tmp[:-2]

                            str += str_tmp
                        if cast_done == True: #len(entry[Generator.CAST_PTR_NO_MEMBER]) == 1 and cast_done == True:
                            if self.debug_vars_init:
                                logging.info("Returning after detecting a cast")
                            return str, alloc
                    alloc = True
        else:
            if (level == 0 and skip_init == False) or cl in [ "builtin", "enum" ]:
                fuzz = int(self._to_fuzz_or_not_to_fuzz(type))
                typename = self._get_typename_from_type(type)
                if typename in ["struct", "enum", "union"]: # annonymous type
                    typename = name
                
                
                null_terminate = False
                tag = False
                value = None
                min_value = None
                max_value = None
                
                mul = 1
                isPointer = False
                if level == 0 and self.init_data is not None and entity_name in self.init_data:
                    if self.debug_vars_init:
                        logging.info(f"Detected that {entity_name} has user-provided init")
                    item = self.init_data[entity_name]
                    for entry in item["items"]:
                        entry_type = "unknown"
                        if "type" in entry:
                            entry_type = entry["type"]
                            if " *" not in entry_type:
                                entry_type = entry_type.replace("*", " *")
                  
                        if name in entry["name"] or entry_type == self._get_typename_from_type(type):
                            if self.debug_vars_init:
                                logging.info(f"In {entity_name} we detected that item {name} of type {entry_type} has a user-specified init")
                            if "nullterminated" in entry:
                                if entry["nullterminated"] == "True":
                                    null_terminate = True
                            if "tagged" in entry:
                                if entry["tagged"] == "True":
                                    tag = True
                            if "value" in entry:
                                value = entry["value"]
                            if "min_value" in entry:
                                min_value = entry["min_value"]
                            if "max_value" in entry:
                                max_value = entry["max_value"]
                            if "user_name" in entry:
                                name = entry["user_name"]
                            if "size" in entry:
                                mul = entry["size"]
                                if "size_dep" in entry:
                                    # check if the dependent param is present (for functions only)
                                    dep_id = entry["size_dep"]["id"]
                                    dep_add = entry["size_dep"]["add"]
                                    dep_names = []
                                    dep_user_name = ""
                                    dep_found = False
                                    for i in item["items"]:
                                        if i["id"] == dep_id:
                                            dep_names = i["name"]
                                            if "user_name" in i:
                                                dep_user_name = i["user_name"]
                                            else:
                                                logging.error("user_name not in data spec and size_dep used")
                                                sys.exit(1) 
                                            dep_found = True
                                            break
                                    if dep_found and fid:
                                        f = self.fnidmap[fid]
                                        if f is not None and len(dep_names) > 0:
                                            for index in range(1, len(f["types"])):
                                                if "name" in f["locals"][index - 1] and f["locals"][index - 1]["parm"]:
                                                    param_name = f["locals"][index - 1]["name"]
                                                    if param_name in dep_names:
                                                        mul = dep_user_name
                                                        if dep_add != 0:
                                                            mul = f"{mul} + {dep_add}" 


                            if "pointer" in entry:
                                if entry["pointer"] == "True":
                                    isPointer = True
                            user_init = True
                            break # no need to look further
                tagged_var_name = 0
                if tag:
                    tagged_var_name = self._get_tagged_var_name() 
                if not isPointer:
                    str += "aot_memory_init(&{}, sizeof({}), {} /* fuzz */, {});\n".format(
                        name, typename, fuzz, tagged_var_name)
                else:
                    # special case: non-pointer value is to be treated as a pointer
                    str += f"{typename}* {name}_ptr;\n"
                    str += f"aot_memory_init_ptr(&{name}_ptr, sizeof({typename}), {mul}, 1 /* fuzz */, {tagged_var_name});\n"
                    str += f"{name} = {name}_ptr;\n"
            
                if value is not None:
                    str += "#ifdef KLEE\n"
                    str += "if (AOT_argc == 1) {\n"
                    str += f"    klee_assume({name} == {value});\n"
                    str += f"    klee_skip_tag();\n"
                    str += "}\n"
                    str += "#endif\n"
                if min_value is not None:
                    str += f"if ({name} < {min_value}) {name} = {min_value};\n"
                if max_value is not None:
                    str += f"if ({name} > {max_value}) {name} = {max_value};\n"
                if tag:
                    if not isPointer:
                        str += f"aot_tag_memory(&{name}, sizeof({typename}), 0);\n"
                    else:
                        str += f"aot_tag_memory({name}_ptr, sizeof({typename}) * {mul}, 0);\n"

        if cl == "record" and t_id not in self.used_types_data and level > 1:
            typename = self._get_typename_from_type(self.typemap[t_id])
            return f"// {name} of type {typename} is not used anywhere\n", False


        # if level == 0 and skip_init == False:
        #     str += "if (aot_check_init_status(\"{}\", {}))\n".format(name, res_var)
        #     str += "\treturn -1;\n"

        # now that we have initialized the top-level object we need to make sure that
        # all potential pointers inside are initialized too
        # TBD
        # things to consider: pointer fields in structs, members of arrays
        # it seems we need to recursively initialize everything that is not a built-in type
        go_deeper = False
        if cl not in [ "builtin", "enum" ]:
            # first, let's check if any of the refs in the type is non-builtin
            refs = []
            if self.used_types_only and cl == "record":
                refs = type["usedrefs"]
            else:
                refs = type["refs"]

            for t_id in refs:
                tmp_t = self.typemap[t_id]
                if tmp_t:
                    tmp_t = self._get_typedef_dst(tmp_t)
                    if tmp_t["class"] != "builtin":
                        go_deeper = True
                        break

            if go_deeper == False:
                if "usedrefs" in type and cl != "pointer" and cl != "enum":
                    for u in type["usedrefs"]:
                        if u != -1:
                            go_deeper = True
                            break
            
            if go_deeper:
                alloc_tmp = False
                if is_array:
                    # in case of arrays we have to initialize each member separately
                    index = f"i_{level}"
                    # assuming an array has only one ref
                    member_type = type["refs"][0]
                    member_type = self.typemap[member_type]
                    if (count is None and loop_count > 1) or cl == "const_array" or cl == "incomplete_array":
                        # please note that the loop_count could only be > 0 for an incomplete array if it 
                        # was artificially increased in AoT; normally the size of such array in db.json would be 0
                        str += f"for (int {index} = 0; {index} < {loop_count}; {index}++) ""{\n"
                    skip = False
                    if member_type["class"] == "const_array":
                        # const arrays are initialized with enough space already;
                        # we need to pass that information in the recursive call so that
                        # redundant allocations are not made
                        skip = True
                    if cl == "pointer":
                        skip = True

                    tmp_name = ""
                    if (count is None and loop_count > 1) or cl == "const_array" or cl == "incomplete_array":
                        tmp_name = f"{name}[{index}]"
                    else:
                        tmp_name = name
                    if name_change:
                        tmp_name = f"(*{tmp_name})"
                    if self.debug_vars_init:
                        logging.info(f"variant E, my type is {type['id']}, loop_count is {loop_count}, cl is {cl}: {tmp_name}")
                    str_tmp, alloc_tmp = self._generate_var_init(f"{tmp_name}",
                                                                 member_type,
                                                                 res_var,
                                                                 pointers[:],
                                                                 level + 1,
                                                                 skip,
                                                                 known_type_names=known_type_names,
                                                                 cast_str=cast_str,
                                                                 new_types=new_types,
                                                                 init_obj=init_obj,
                                                                 fuse=fuse)
                    str += str_tmp
                else:
                    # this is not an array
                    # I am not sure at this point if we could have something else
                    # than record or a pointer, but C keeps surprising
                    # pointers are already handled as arrays, so we are left with
                    # records

                    if cl == "record":
                        # remember that we initialized this record
                        _t_id = type["id"]
                        pointers.append(type["id"])
                        if _t_id in self.dup_types:
                            dups = [ d for d in self.dup_types[_t_id] if d != _t_id ]
                            for d in dups:
                                pointers.append(d)
                                
                        if skip_init:
                            deref_str = "->"
                        else:
                            deref_str = "."
                        # inside the record we will have to find out which of the members
                        # have to be initialized

                        tmp_name = name
                        if name_change:
                            tmp_name = f"(*{tmp_name})"

                        # get the info on bitfields
                        bitfields = {}
                        for i, bitcount in type["bitfields"].items():
                            index = int(i)
                            if ("usedrefs" in type) and (-1 != type["usedrefs"][index]):
                                bitfields[index] = bitcount

                        # since bitfields are initialized by assignment, we have to use struct initializer
                        # this is necessary in order to avoid issues with const pointer members
                        # because the initializer construct zero-initializes all non-specified members,
                        # we initialize all the used bit fields first, then the rest of the struct members
                        str_tmp = ""
                        if len(bitfields) != 0:
                            str_tmp += f"{tmp_name} = ({typename})" + "{"
                            if skip_init and (False == name_change):
                                str_tmp = f"*({typename}*){str_tmp}"

                        for i, bitcount in bitfields.items():
                            field_name = type["refnames"][i]
                            tmp_tid = type["refs"][i]
                            tmp_t = self._get_typedef_dst(
                                self.typemap[tmp_tid])
                            # we can generate bitfield init straight away as bitfields are integral types, therefore builtin
                            str_tmp += f".{field_name} = aot_memory_init_bitfield({bitcount}, 1 /* fuzz */, 0), "

                        if len(bitfields) != 0:
                            # remove last comma and space
                            str_tmp = str_tmp[:-2]
                            str_tmp += "};\n"
                            str += str_tmp

                        # if _t_id in self.member_usage_info:
                        #     logging.info(f"Discovered that type {type['str']} is present in the size info data")
                        #     # ok, so we are operating on a record type (a structure) about which we have some additional data
                        #     # the main type of data we have is about the relationship between pointers inside the struct
                        #     # and the corresponding array sizes (which might be constant or represented by other struct members, e.g.buf <-> buf_size)
                        #     # what we have to do is to analyze which data we have, order the init of
                        #     # struct members accordingly and make sure the right size constraints are used during the initialization
                        #     _member_info = self.member_usage_info[_t_id]
                        #     for i in range(len(_member_info)):
                        #         if len(_member_info[i]):
                        #             logging.info(f"We have some data for {type['refnames'][i]} member")
                        
                        members_order, size_constraints = self._get_members_order(type)
                        member_to_name = {}
                        for i in members_order:

                            field_name = type["refnames"][i]

                            #is_typedecl = False
                            # if i in type["decls"]:
                            #    # some of the members are type declarations, so we skip them as there is
                            #    # no way to initialize
                            #    pass
                            if field_name == "__!attribute__":
                                # refnames for attributes can be skipped as they are metadata
                                continue

                            if field_name == "__!anonrecord__" or field_name == "__!recorddecl__" or field_name == "__!anonenum__":
                                # record definitions can be skipped
                                continue

                            is_in_use = self._is_member_in_use(type, tmp_name, i)
                            
                            if is_in_use:
                                tmp_tid = type["refs"][i]
                                obj = init_obj
                                if init_obj is not None:
                                    if init_obj.t_id in init_obj.used_members:
                                        if i in init_obj.used_members[init_obj.t_id]:
                                            if self.debug_vars_init:
                                                logging.info(f"Member use info detected for {init_obj} member {i}")
                                            obj = init_obj.used_members[init_obj.t_id][i]
                                        #else :
                                        #    logging.info(f"Current init object data found, but member {i} not used")
                                        #    continue
                                    else:
                                        if self.debug_vars_init:
                                            logging.info(f"Could not find member {i} use info in obj tid {init_obj.t_id}")
                                        #continue
                                    # note: currently, if we can't find the member in the current object, we fall back
                                    # to the global member data, which might produce unnecessary inits

                                tmp_t = self._get_typedef_dst(
                                    self.typemap[tmp_tid])
                                # if tmp_t["class"] != "builtin":

                                # going deeper
                                if "__!anonrecord__" in tmp_name:
                                    tmp_name = tmp_name.replace(
                                        "__!anonrecord__", "")
                                    deref_str = ""

                                if cast_str != None:
                                    tmp_name = f"(({cast_str}){tmp_name})"
                                    cast_str = None

                                count = None
                                size_member_used = False                                
                                if len(size_constraints[i]) > 0:
                                    if "size_member" in size_constraints[i]:
                                        _member = size_constraints[i]["size_member"]
                                        if _member in member_to_name:
                                            count = member_to_name[_member]
                                            size_member_used = True
                                    elif "size_member_idx" in size_constraints[i]:
                                        _member = size_constraints[i]["size_member_idx"]
                                        if "max_val" in size_constraints[_member]:
                                            count = size_constraints[_member]["max_val"] + 1
                                    elif "size_value" in size_constraints[i]:
                                        count = size_constraints[i]["size_value"]

                                if i in bitfields:
                                    continue
                                else:
                                    # let's see if we might be dealing with casted pointers
                                    entry, single_init, offset_types = self._get_cast_ptr_data(
                                        type, i)
                                    skip = False
                                    if self.debug_vars_init:
                                        logging.info(f"single_init is {single_init}")
                                        
                                    if entry is not None:
                                        # passing skip_init as True in order to prevent
                                        # further initialization of void* as we are handling it here
                                        skip = True
                                    if not single_init:
                                        if self.debug_vars_init:
                                            logging.info("variant a")
                                        member_to_name[i] = f"{tmp_name}{deref_str}{field_name}"                                                                           
                                        str_tmp, alloc_tmp = self._generate_var_init(f"{tmp_name}{deref_str}{field_name}",
                                                                                     tmp_t,
                                                                                     res_var,
                                                                                     pointers[:],
                                                                                     level,
                                                                                     skip_init=skip,
                                                                                     known_type_names=known_type_names,
                                                                                     cast_str=cast_str,
                                                                                     new_types=new_types,
                                                                                     init_obj=obj,
                                                                                     fuse=fuse,
                                                                                     count=count)
                                        if size_member_used:
                                            str += "// smart init: using one struct member as a size of another\n"
                                        str += str_tmp
                                        str += self._generate_constraints_check(f"{tmp_name}{deref_str}{field_name}", size_constraints[i])

                                    if entry is not None:
                                        if self.debug_vars_init:
                                            logging.info("variant b")
                                        variant = ""
                                        variant_num = 1
                                        for dst_tid in entry[i]:
                                            dst_t = self.typemap[dst_tid]
                                            typename = self._get_typename_from_type(
                                                dst_t)

                                            active_type = self.typemap[self._get_real_type(tmp_tid)]
                                            active_type = self._get_typedef_dst(active_type)                                    
                                            casted_type = self.typemap[self._get_real_type(dst_tid)]
                                            casted_type = self._get_typedef_dst(casted_type)
                                            struct_types = [ "record", "record_forward" ]
                                            if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                                if self.debug_vars_init:
                                                    logging.info("will not consider cast of structural type to non-structural type")
                                                continue

                                            if new_types != None:
                                                new_types.add(dst_tid)
                                            # generate an alternative init for each of the detected casts
                                            str_tmp, alloc_tmp = self._generate_var_init(f"{tmp_name}{deref_str}{field_name}",
                                                                                         dst_t,
                                                                                         res_var,
                                                                                         pointers[:],
                                                                                         level,
                                                                                         False,
                                                                                         known_type_names=known_type_names,
                                                                                         cast_str=typename,
                                                                                         new_types=new_types,
                                                                                         init_obj=obj,
                                                                                         fuse=fuse,
                                                                                         count=count)
                                            if not single_init:
                                                variant = f"variant {variant_num}"
                                                variant_num += 1
                                            else:
                                                member_to_name[i] = f"{tmp_name}{deref_str}{field_name}"
                                            if size_member_used:
                                                str_tmp = f"// smart init: using one struct member as a size of another\n{str_tmp}"
                                            str_tmp += self._generate_constraints_check(f"{tmp_name}{deref_str}{field_name}", size_constraints[i])

                                            str_tmp = f"\n// smart init (b) {variant}: we've found that this pointer var is casted to another type: {typename}\n{str_tmp}"
                                            #logging.info(str_tmp)
                                            if not single_init:
                                                str_tmp = str_tmp.replace(
                                                    "\n", "\n//")
                                                if str_tmp.endswith("//"):
                                                    str_tmp = str_tmp[:-2]
                                            str += str_tmp
                                            
                            # else:
                            #    str += f"// {name}{deref_str}{field_name} never used -> skipping init\n"
                    else:
                        logging.error(
                            f"Unexpected deep var class {cl} for {name}")
                        #sys.exit(1)
            else:
                str += f"// didn't find any deeper use of {name}\n"

        prefix = ""
        if level != 0:
            for i in range(level):
                prefix += "  "
            str = prefix + str
            str = str.replace("\n", f"\n{prefix}")
            str = str[:-(2*level)]

        if is_array and go_deeper and ((count is None and loop_count > 1) or cl == "const_array" or cl == "incomplete_array"):
            str += f"{prefix}""}\n"  # close the for loop

        return str, alloc

    # -------------------------------------------------------------------------

    def _generate_var_deinit(self, var):
        return f"aot_memory_free_ptr(&{var});\n"

    # -------------------------------------------------------------------------

    # Given a function id, generate code that calls the function with the right
    # arguments
    # For example:
    # in: int foo(int)
    # out:
    # int x; // possibly with some init
    # int ret_foo = foo(x);
    # if create_params is False we only generate function call with the
    # original param names, e.g.
    # int foo ( int x ) -> foo (x)

    def _generate_function_call(self, function_id, static=False, create_params=True, param_names=None, known_type_names=None, new_types=None):
        # in order to generate a correct call we need to know:
        # - returned type
        # - types of function parameters
        # - function name
        function = self.fnidmap[function_id]
        if self.afl == 'stores':
            param_names = ['dev', 'attr', 'buf', 'count']
        elif self.afl == 'genl_ops':
            param_names = ['skb', 'info']

        name = function["name"]

        str = "\n// Call site for function '{}'\n".format(name)

        if create_params:
            # put everything in braces to avoid name collision
            str += "{\n"

        # the return type goes first in the "types" array
        type_ids = function["types"][:]
        return_present = True
        first_type = self.typemap[type_ids[0]]
        if first_type["class"] == "builtin" and first_type["str"] == "void":
            return_present = False

        if not create_params and return_present:
            str += "return "

        # let's check if we might have a user-provided init for this function
        index_mapping = {}
        order_to_user_name = {}
        param_to_user_name = {}
        reorder = False
        i = 0
        for i in range(len(type_ids)):
            # as some params might be reorered we need to keep track of the new mapping
            index_mapping[i] = i

        if name in self.init_data and param_names is None:
            user_init_data = self.init_data[name] 
            order_to_names = {}
            ord_index = 0
            if "order" in user_init_data:
                for i in user_init_data["order"]:
                    for item in user_init_data["items"]:
                        if i == item["id"]:
                            order_to_names[ord_index] = item["name"]
                            if "user_name" in item:
                                order_to_user_name[ord_index] = item["user_name"]
                            
                            ord_index += 1
                            break
            # we now have a matching order, let's find the corresponding function args
            logging.debug(f"order_to_names {order_to_names} order_to_user_name {order_to_user_name} ")
            order_to_params = {}
            for i in range(1, len(type_ids)): # 1 -> let's skip the return type
                varname = ""
                if "name" in function["locals"][i-1] and function["locals"][i-1]["parm"]:
                    tmp = function["locals"][i-1]["name"]
                    if tmp != "":
                        varname = function["locals"][i-1]["name"]
                        logging.debug(f"varname is {varname}")
                        for ord in order_to_names:
                            if varname in order_to_names[ord]:
                                order_to_params[ord] = i
                                logging.debug(f"order_to_params[{ord}] = {i}, tid = {type_ids[i]}")
                                if ord in order_to_user_name:
                                    param_to_user_name[i] = order_to_user_name[ord]
                            else:
                                logging.debug(f"varname {varname} not in order_to_names[{ord}]")
            logging.debug(f"Order to names: {order_to_names}:")
            logging.debug(f"Order to params: {order_to_params}")
            order_to_params_sorted = collections.OrderedDict(sorted(order_to_params.items()))
            logging.debug(f"Order to params sorted: {order_to_params_sorted}")
        
 
            partial_order = []

            for ord in order_to_params_sorted:
                partial_order.append(order_to_params_sorted[ord])
            # partial_order now contains selected indices in the type_ids array sorted 
            # according to the order found in the user data
            
            # check if we need to reorder anything
            reorder = False
            for i in range (1, len(partial_order)):
                if partial_order[i] < partial_order[i-1]:
                    reorder = True
                    break

            if reorder:
                to_add = [] # we shall remove those params from the list and add them
                            # sorted at the end
                i = 0
                for index in partial_order:
                    to_add.append(type_ids[index])
                    val = index_mapping[index]
                    index_mapping[index] = -1
                    index_mapping[len(type_ids) + i] = val # remember the old index of this param
                    i += 1
                    type_ids[index] = -1 # mark that this param is moved
                for tid in to_add:
                    type_ids.append(tid)       
            #index_mapping = {}
            
            logging.debug(f"partial order: {partial_order}")
            logging.debug(f"User data for {name}: {user_init_data}")
            logging.debug(f"index_mapping = {index_mapping}")
            logging.debug(f"param to user name: {param_to_user_name}")
            logging.debug(f"type_ids {type_ids}")
           
        # once we know the types, we have to declare several variables:
        # one for storing the returned value (if not void) and one per
        # each input parameter
        i = 0
        param_to_varname = {}
        varnames = []
        vartypes = []
        alloced_vars = []
        alloc = False
        start_index = 0
        
        
        if create_params:
            res_var = "_init_res"
            str += "int {} = 0;\n".format(res_var)
            for tid in type_ids:
                type = self.typemap[tid]
                saved_i = i
                if i == 0 and not return_present:
                    i += 1
                    continue

                if tid == -1: # this param was reordered
                    i += 1                    
                    varnames.append("_aot_reordered_param")
                    vartypes.append(type)
                    continue

                varname = ""
                if i == 0:
                    varname += "ret_value"
                else:
                    #if name in self.init_data and param_names is None:
                    i = index_mapping[i]
                    if param_names == None:
                        #varname += "param_{}".format(i)

                        if i in param_to_user_name:
                            varname = param_to_user_name[i]
                        else:
                            n = "param_{}".format(i)
                            if "name" in function["locals"][i-1] and function["locals"][i-1]["parm"]:
                                tmp = function["locals"][i-1]["name"]
                                if tmp != "":
                                    n = function["locals"][i-1]["name"]
                            varname += n
                    else:
                        # if the user provided concrete param names, use them
                        # instead of the generic ones
                        varname += "{}".format(param_names[i-1])
                if saved_i != i:
                    varnames[i] = varname
                    vartypes[i] = type
                else:                
                    varnames.append(varname)
                    vartypes.append(type)
                logging.debug(f"Generating var def for varname {varname}")
                str += self._generate_var_def(type, varname)
                str += "\n"
                if i != 0:
                    if self.afl == 'stores' and varname in ['buf', 'count']:
                        if varname == 'buf':
                            fuzz = 1  # arbitrarily turning on fuzzing
                            buf_init = f'aot_memory_init_ptr(&buf, 4096, {self.ptr_init_size} /* count */, {fuzz} /* fuzz */, 0);'
                            str += buf_init
                            alloced_vars.append(varname)
                            str += "\n"
                        elif varname == 'count':
                            str += self._load_snippet("stores_var_init")

                    elif self.afl == 'genl_ops' and varname in ['info']:
                        alloc = False
                        pointers = []
                        tmp, alloc = self._generate_var_init(
                            varname, type, res_var, pointers, known_type_names=known_type_names, 
                            new_types=new_types,entity_name=name, fuse=0)
                        str += tmp
                        if alloc:
                            alloced_vars.append(varname)
                        str += "\n"
                        str += self._load_snippet("genl_ops_var_init")

                    else:
                        alloc = False
                        pointers = []
                        # let's check if the param is used at all, if not, let's skip the init just like that
                        is_used = function["locals"][i-1]["used"]
                        if is_used:
                            init_obj = None
                            if function_id in self.funcs_init_data:
                                init_data = self.funcs_init_data[function_id]
                                param_tid, init_obj = init_data[i - 1]
                            tmp, alloc = self._generate_var_init(
                                varname, type, res_var, pointers, known_type_names=known_type_names, new_types=new_types,entity_name=name,
                                init_obj=init_obj, fuse=0, fid=function_id)
                        else:
                            tmp = f"// Detected that the argument {varname} is not used - skipping init\n"
                        str += tmp
                        if alloc:
                            alloced_vars.append(varname)
                        str += "\n"

                    if self.dynamic_init:
                        
                        RT,TPD = self._resolve_record_type(type["id"])
                        if RT is not None and type["class"]=="pointer":
                            # Replace the initialized variable with the image from kflat
                            if "abs_location" in function and len(function["abs_location"]) > 0:
                                loc = os.path.basename(function["abs_location"].split(":")[0])
                            else:
                                loc = os.path.normpath(function["location"].split(":")[0])
                                if os.path.isabs(loc):
                                    if self.source_root is not None and len(self.source_root) > 0:
                                        loc = loc[len(self.source_root)+1:]
                                    else:
                                        assert 0, "Detected absolute location in function location (%s) but the 'source root' parameter is not given"%(function["location"])
                            vartype = " ".join(self._generate_var_def(type, varname).split()[:-1])
                            str += Generator.DYNAMIC_INIT_FUNCTION_VARIABLE_TEMPLATE.format(varname, "flatten", f"_func_arg_{i}", vartype)+"\n\n"
                i = saved_i
                i += 1

            if return_present:
                # varnames[0] -> return var name
                start_index = 1

            # Handle AoT Recall mode
            interface = None
            interface_types = ["read", "write", "show", "store", "ioctl"]
            if name in self.init_data:
                if "interface" in self.init_data[name]:
                    interface = self.init_data[name]["interface"]

            str += f"// Save data necessary to generate PoC\n"
            if interface is not None and interface in interface_types:
                str += f"AOT_RECALL_SAVE_INTERFACE(\"{interface}\");\n"
            
            for n in range(start_index, len(varnames)):
                # Save address to variables that aren't pointers
                # In IOCTL handlers 'arg' is pointer casted to integer so treat it as such
                if vartypes[n]["class"] == "pointer" or (interface == "ioctl" and varnames[n] == "arg"):
                    varname = varnames[n]
                else:
                    varname = f'&{varnames[n]}'
                str += f'AOT_RECALL_SAVE_ARG({varname});\n'
            str += '\n'

            # Create return value
            if return_present:
                # varnames[0] -> return var name
                str += "{} = ".format(varnames[0])
        else:
            # when we don't generate parameters we extract the names
            # from db.json
            for l in function["locals"]:
                if l["parm"]:
                    varnames.append(l["name"])

        if static:
            # in case of static functions we call their generated wrappers instead
            name = "wrapper_{}_{}".format(name, function_id)
        str += "{}(".format(name)
        
        for n in range(start_index, len(varnames)):
            str += varnames[n]
            if n != len(varnames) - 1:
                str += ", "

        str += ");\n"

        for var in alloced_vars:
            str += self._generate_var_deinit(var)

        if create_params:
            str += "}\n"

        

        return str

    # -------------------------------------------------------------------------

    # Given a function id, generate a function stub
    def _generate_function_stub(self, function_id, stubs_file=False, fpointer_stub=False,
                                stub_name=None):
        function = None
        static = False
        name = stub_name
        func_name = ""
        i = 0
        TYPE_FUNC = 1
        TYPE_FUNCDECL = 2
        TYPE_UNRESOLVED = 3
        TYPE_FPOINTER = 4
        original_fbody = None

        if False == fpointer_stub:
            function = self.fnidmap[function_id]
            t = TYPE_FUNC
            if function is None:
                logging.warning(
                    f"Unable to find function id {function_id}, will try funcdecl")
                function = self.fdmap[function_id]
                if function is None:
                    logging.warn(
                        f"Unable to find function is {function_id} in funcdecls, trying unresolved")
                    function = self.umap[function_id]
                    if function is None:
                        logging.error(
                            f"Can't find function with id {function_id}")
                        return ""
                    else:
                        t = TYPE_UNRESOLVED
                else:
                    t = TYPE_FUNCDECL

            name = function["name"]
            static = False
            if t != TYPE_UNRESOLVED and function["linkage"] == "internal":
                static = True
            if not stubs_file and not static:
                # non-static functions go to stubs file
                return ""
        else:
            # in this mode we wish to generate a function stub for a function pointer
            t = TYPE_FPOINTER

        str = "\n// Stub code\n"
        return_type = None
        if t == TYPE_FUNC:
            decl = function["declbody"]
            str += decl
            func_name = function["name"]
            return_type = self.typemap[function["types"][0]]
            original_fbody = function["body"][len(decl):]
            original_fbody = original_fbody.replace("{", "", 1)
            before, sep, after = original_fbody.rpartition("}")
            original_fbody = before.replace("\n", "\n\t")
        elif t == TYPE_FUNCDECL or t == TYPE_FPOINTER:
            if t == TYPE_FUNCDECL:
                return_type = self.typemap[function["types"][0]]
                # we use signature as it guarantees no parameter names
                tmp = function["signature"]
                copy = function["signature"]
                # sometimes it happens that function decl line doesn't have param names
                # let's try to detect that and generate them
                numargs = len(function["types"]) - 1
                i = 0

                # in the signature, the function's name comes first
                index = tmp.find(name)
                func_name = ""
                if index != -1:  # that should always be the case
                    end_index = tmp[index:].find(" ") + index
                    func_name = tmp[index:end_index]
                    index = end_index + 1
                else:
                    logging.error(
                        f"Unable to find function name in the signature for fid {function_id}")
                    shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")
                    sys.exit(1)

                # after the name, we have the function type
                end_index = tmp[index:].find("(") + index
                func_type = tmp[index:end_index]
                index = end_index
            else:
                # in the TYPE_FPOINTER mode, rather than passing id to a function we
                # pass id of a function type
                f_type = self.typemap[function_id]
                if f_type == None:
                    logging.error(
                        f"Unable to locate function type {function_id}")
                    shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")
                    sys.exit(1)
                return_type = self.typemap[f_type["refs"][0]]

                if stub_name != None:
                    func_name = stub_name
                else:
                    func_name = "fpointer_stub"
                tmp = f_type["def"]

                index = 0
                end_index = tmp.find("(")
                func_type = tmp[index:end_index].strip()
                index = end_index
                end_index = tmp[index:].find(")") + index

                if end_index == index + 1:
                    numargs = 0
                else:
                    numargs = tmp[index:end_index].count(",") + 1

            # we now construct funcdecl string without param names
            tmp = f"{func_type} {func_name}{tmp[index:]}"
            copy = tmp[:]
            index = len(func_type) + len(" ") + len(func_name) + 1
            while (i < numargs):
                if i != numargs - 1:
                    end = tmp[index:].find(",") + index
                else:
                    end = tmp[index:].find(")") + index
                arg = tmp[index:end].strip()
                logging.debug(
                    f"arg is {arg} numargs is {numargs} index is {index} end is {end} name is {copy}")
                if arg != "void":
                    if arg != "...":
                        copy = copy[:index] + \
                            copy[index:].replace(arg, f"{arg} param_{i}", 1)
                        end += len(f" param_{i}")
                    else:
                        end += 1
                    tmp = copy

                    index = tmp[end:].find(",") + end + 1
                i = i + 1

            # one more thing to handle: cases where we have asm("func") in the declaration, e.g.
            # size_t __real_strlcpy(char * param_0, const char * param_1, size_t param_2) asm("strlcpy")
            copy = self._filter_out_asm_in_fdecl(copy)

            str += copy
        else:  # TYPE_UNRESOLVED
            func_name = function["name"]
            str += func_name + "()"

        if stubs_file:
            # no extern functions in the stubs file
            str = str.replace("extern ", "")

        if static and stubs_file:
            # a stub defined in a stub file for a static (possibly inline) function
            str = str.replace(f" {name}(", f" wrapper_{name}_{function_id}(")
            str = str.replace(f" {name} (", f" wrapper_{name}_{function_id} (")
            # sometimes the name is connected with the pointer char
            str = str.replace(f"*{name}(", f"*wrapper_{name}_{function_id}(")
            str = str.replace(f"*{name} (", f"*wrapper_{name}_{function_id} (")

            # since we call the function from stubs file from other files it needs to be non-static, non-inline
            str = str.replace("static ", "")
            str = str.replace("inline ", "")

            func_name = f"wrapper_{func_name}_{function_id}"

        inline = 0
        if t == TYPE_FUNC and "inline" in function: 
            inline = function["inline"]

        str += " {\n"

        str += "\t// stub implementation\n"
        if function_id in self.all_funcs_with_asm:
            str += "\t// note: original function's implementation contains assembly\n"
            self.stubs_with_asm.add(func_name)

        if static and inline != 1 and not stubs_file: # and function_id not in self.all_funcs_with_asm:
            # a stub of a a static function in a non-stub file -> call the wrapper
            tmp = self._generate_function_call(
                function_id, static=True, create_params=False)
            str += tmp.replace("\n", "\n\t")
        else:
            str += f"\taot_log_msg(\"Entered function stub {name}\\n\");\n"
#            str += f"\texit(0);\n"
            if original_fbody:
                str += "\t// Function's original body\n//"
                str += original_fbody.replace("\n", "\n//")
                str += "\n\t // End of function's orignal body\n"

        if return_type != None:
            orig_return_type = return_type
            orig_cl = return_type["class"]
            return_type = self._get_typedef_dst(return_type)
            null_pointer = ["pointer", "decayed_pointer", "function",
                            "const_array", "incomplete_array", "variable_array"]
            cl = return_type["class"]
            if cl in null_pointer:
                counter = len(self.stub_to_return_ptr)
                # we return an address from a specially mapped memory region -> see aot_fuzz_lib.c for the details
                # each function stub returns an address separated by a page size (0x1000)
                # this is used to recognize which function stub caused a failure (as further offsets might be applied to the 
                # original base address returned by the stub, e.g. ptr = stub(); ptr->member = x;

                if self.stubs_for_klee:
                    # NOTE: for KLEE we do  special trick: in order to mark that the failure is caused by
                    # the user data (i.e. lack of stub), we introduce a dummy symbolic object into constraints
                    str += "\t#ifdef KLEE\n"
                    str += "\tint* ptr;\n"
                    str += "\taot_memory_init_ptr(&ptr, sizeof(int), 1, 1, \"stubptr\");\n"
                    str += "\taot_tag_memory(ptr, sizeof(int), 0);\n"
                    str += "\tif (*ptr) {\n"
                    str += "\t\t*ptr = 0;\n"                                                  
                    str += "\t}\n"
                    str += "\t#endif\n"                                                              

                val = Generator.AOT_SPECIAL_PTR + (counter * (2*Generator.AOT_SPECIAL_PTR_SEPARATOR)) 
                self.stub_to_return_ptr[func_name] = val
                str += f"\treturn {hex(val)}; // returning a special pointer"
                logging.info("Will generate return statement 1")
            elif cl == "builtin":
                if return_type["str"] != "void":
                    str += "\treturn 0; // returning zero value for a builtin type\n"
                    logging.info("Will generate return statement 2")
            elif cl == "enum" or cl == "enum_forward":
                if cl == "enum":
                    str += f"\treturn {return_type['values'][0]}; // returning the first value of the enum\n"
                else:
                    str += f"\treturn 0;\n"
                logging.info("Will generate return statement 3")
            else:
                # that's a struct / union returned by value
                if orig_cl == "typedef":
                    str += f"{orig_return_type['name']} ret;\n"
                elif return_type["str"] == "":
                    str += f"\t{return_type['def']} ret;\n"
                else:
                    if return_type["union"]:
                        str += "\tunion "
                    else:
                        str += "\tstruct "
                    str += f"{return_type['str']} ret;\n"
                str += f"\tmemset(&ret, 0, sizeof(ret));\n"
                str += "\t return ret;\n"
                logging.info("Will generate return statement 4")

        str += "\n}\n"
        if self.dynamic_init and (not static or not stubs_file):
            if function is not None and ("inline" not in function or function["inline"] is not True):
                str += "%s\n"%(self._get_function_pointer_stub(function))
        if stubs_file:
            self.generated_stubs += 1
        if t != TYPE_FPOINTER:
            return str
        else:
            return str, func_name

    # -------------------------------------------------------------------------

    def _load_snippet(self, name):
        snippet_path = f"{os.path.abspath(os.path.dirname(sys.argv[0]))}/resources/{name}.snippet"

        if not os.path.isfile(snippet_path):
            logging.error(f"Snippet {snippet_path} not found!")
            return f"// Snippet {snippet_path} not found\n"

        with open(snippet_path, "r") as f:
            return f.read() + "\n\n"


    # -------------------------------------------------------------------------

    @staticmethod
    def _sort_order(a, b):
        if a["id"] < b["id"]:
            return -1
        elif a["id"] > b["id"]:
            return 1
        else:
            return 0

    def _collect_derefs_trace(self, f_id, functions):
        # we process functions in DFS mode - starting from f_id and within the scope of the 'functions' set
        # this is supposed to resemble normal sequential execution of a program
        # within each of the functions we need to establish the right order of derefs and function calls
        # since function calls can preceed certain derefs and we operate in a DFS-like way

        DEREF="deref"
        CALL="call"
        derefs_trace = []
        
        f = self.fnidmap[f_id]
        if f is None:
            return derefs_trace
        self.debug_derefs(f"Collecting derefs for function {f['name']}")
        # first we need to establish a local order of funcs and derefs
        ordered  = []
        ord_to_deref = {}
        for d in f["derefs"]:
            ords = []
            if isinstance(d["ord"], list):
                ords = d["ord"]
            else: # ord is just a number
                ords.append(d["ord"])
            for o in ords:
                ordered.append({"type": DEREF, "id": o, "obj": d})  
                self.debug_derefs(f"Appending deref {d}")              
                if o in ord_to_deref:
                    logging.error("Didn't expect ord to reappear")
                ord_to_deref[o] = d
        for i in range(len(f["call_info"])):
            c = f["call_info"][i]
            call_id = f["calls"][i]
            if call_id in functions:
                ords = []
                if isinstance(c["ord"], list):
                    ords = c["ord"]
                else: # ord is just a number
                    ords.append(c["ord"])
                for o in ords:
                    # note: if the deref happens several times in the trace, it will have several entries
                    # in the ord list -> one per each occurrence
                    # below we duplicate the occurrences according to their order in the trace
                    ordered.append({"type": CALL, "id": o, "obj": call_id})
                    self.debug_derefs(f"Appending call {call_id}, ord {o}")
        ordered = sorted(ordered, key=functools.cmp_to_key(Generator._sort_order))


        # ideally we would like to have member dereferences go _before_ casts so that we can 
        # match them accordingly
        # in db.json casts can contain member dereferences which are located _after_ the cast in the derefs trace
        # the pass below is meant to rectify that: put member derefs before the associated casts 
        self.debug_derefs("REORDERING TRACE")
        index = 0 
        while index < len(ordered):
            item = ordered[index]
            if item["type"] == CALL:
                index += 1
                continue
            deref = item["obj"]
            deref_id = int(item["id"]) # id is the deref's order -> see above
            cast_data = self._get_cast_from_deref(deref, f)
            inserts_num = 0
            if cast_data is not None:
                logging.debug("Cast data is not none")
                for t_id in cast_data:
                    for member in cast_data[t_id]:
                        self.debug_derefs(f"MEMBER IS {member} deref is {deref}")
                        if member != Generator.CAST_PTR_NO_MEMBER:
                            # first, we have to find the deref the cast refers to:
                            for oref in deref["offsetrefs"]:
                                if "cast" in oref and oref["kind"] == "member":
                                    dst_deref_id = oref["id"]
                                    # we have the id of the deref that contains the member access
                                    # we now need to find it in the trace
                                    dst_deref = f["derefs"][dst_deref_id]

                                    ords = dst_deref["ord"]
                                    # find the instance with a smallest ord number larger than the current 
                                    # deref id
                                    for o in ords:
                                        found = False
                                        if o > deref_id:
                                            logging.debug("Processing ords...")
                                            # found it!
                                            # we have the order number, let's find the associated 
                                            # deref object                                        
                                            for i in range(len(ordered)):
                                                if ordered[i]["id"] == o:
                                                    # found the associated deref
                                                    # now, let's put that deref just before the currently
                                                    # processed cast
                                                    diff = i - index
                                                    self.debug_derefs(f"Moving item {ordered[i]} to index {index} size is {len(ordered)} diff {diff}")
                                                    ordered[i]["id"] -= diff
                                                    ordered.insert(index, ordered[i])
                                                    deref_id += 1
                                                    inserts_num += 1
                                                    # and remove the current                                                 
                                                    del ordered[i + 1] # +1 since we inserted one element before 
                                                    # we have to update the ids of items that go after the inserted one
                                                    # for j in range(index + 1, len(ordered)):
                                                    #     ordered[j]["id"] += 1
                                                    self.debug_derefs(f"size is {len(ordered)}")
                                                    found = True
                                                    break
                                            
                                            break
                                        if found:
                                            break
            index += inserts_num
            index += 1
        self.debug_derefs("REORDERING CALL REFS")
        # similarly, when there is a cast happening as a result of function return value being modified
        # e.g. B* b = foo() // a* foo()
        # the call happens after the cast in db.json's order -> we want the call to happen first 
        index = 0
        while index < len(ordered):
            item = ordered[index]

            if item["type"] == CALL:
                index += 1
                continue

            deref = item["obj"]
            deref_id = int(item["id"]) # id is the deref's order -> see above
            self.debug_derefs(f"processing deref {deref}")

            inserts_num = 0
            if self._get_callref_from_deref(deref):
                self.debug_derefs("callref detected")
                for oref in deref["offsetrefs"]:
                    if oref["kind"] == "callref":
                        # get the related call order
                        ords = f["call_info"][oref["id"]]["ord"]
                        if not isinstance(ords, list):
                            ords = [ ords ]

                        for o in ords:
                            found = False
                            if o > deref_id:
                                self.debug_derefs("processing ords...")
                                # seems like we've found a call with order 
                                # greater than our cast -> let's move it
                                for i in range(len(ordered)):
                                    if ordered[i]["id"] == o:
                                        # that is our function call                                                
                                        diff = i - index
                                        self.debug_derefs(f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
                                        ordered[i]["id"] -= diff
                                        ordered.insert(index, ordered[i])
                                        deref_id += 1
                                        inserts_num += 1
                                        del ordered[i + 1]
                                        # we have to update the ids of items that go after the inserted one
                                        # for j in range(index + 1, len(ordered)):
                                        #     ordered[j]["id"] += 1
                                        self.debug_derefs(f"size is {len(ordered)}")
                                        found = True

                                break
                            if found:
                                break

                        # cool, we have moved the call to it's right place,
                        # but we still have to handle the call's params: most likely
                        # as their related call they are also located past the cast deref
                        # first let's get their ids:
                        args = f["call_info"][oref["id"]]["args"]
                        # args is a list of ids in our derefs table
                        
                        for _deref_id in args:
                            self.debug_derefs("handling args")
                            deref_obj = f["derefs"][_deref_id]
                            ords = deref_obj["ord"]

                            for o in ords:
                                found = False
                                if o > deref_id:
                                    for i in range(len(ordered)):
                                        if ordered[i]["id"] == o:
                                            diff = i - index
                                            self.debug_derefs(f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
                                            ordered[i]["id"] -= diff
                                            ordered.insert(index, ordered[i])
                                            deref_id += 1
                                            inserts_num += 1
                                            del ordered[i + 1]
                                            # # we have to update the ids of the items that go after the inserted one
                                            # for j in range(index + 1, len(ordered)):
                                            #     ordered[j]["id"] += 1
                                            self.debug_derefs(f"size is {len(ordered)}")
                                            found = True

                                            # once we moved params we also need to move the associated derefs
                                            if ordered[index]["type"] == DEREF:
                                                param_deref = ordered[index]["obj"]
                                                for _oref in param_deref["offsetrefs"]:
                                                    if _oref["kind"] == "member":
                                                        member_deref = f["derefs"][_oref["id"]]
                                                        member_ords = member_deref["ord"]
                                                        for _o in member_ords:
                                                            if _o > deref_id: 
                                                                for _i in range(len(ordered)):
                                                                    if ordered[_i]["id"] == _o:
                                                                        if ordered[_i]["type"] == DEREF and ordered[_i]["obj"]["kind"] == "member":
                                                                            diff = _i - index
                                                                            self.debug_derefs(f"Moving member arg {ordered[_i]} from index {_i} to index {index} size is {len(ordered)} diff {diff}")
                                                                            ordered[_i]["id"] -= diff
                                                                            ordered.insert(index, ordered[_i])
                                                                            deref_id += 1
                                                                            inserts_num += 1
                                                                            del ordered[_i + 1]
                                                                            self.debug_derefs(f"size is {len(ordered)}")
                                                    elif _oref["kind"] == "array":
                                                        array_deref = f["derefs"][_oref["id"]]
                                                        if array_deref["kind"] == "array":
                                                            member_deref = None
                                                            for __oref in array_deref["offsetrefs"]:
                                                                if __oref["kind"] == "member":
                                                                    member_deref = f["derefs"][__oref["id"]]                                                                    
                                                                    break
                                                            if member_deref is not None:
                                                                member_ords = member_deref["ord"]
                                                                for _o in member_ords:
                                                                    if _o > deref_id: 
                                                                        for _i in range(len(ordered)):
                                                                            if ordered[_i]["id"] == _o:
                                                                                if ordered[_i]["type"] == DEREF and ordered[_i]["obj"]["kind"] == "member":
                                                                                    diff = _i - index
                                                                                    self.debug_derefs(f"Moving member arg {ordered[_i]} from index {_i} to index {index} size is {len(ordered)} diff {diff}")
                                                                                    ordered[_i]["id"] -= diff
                                                                                    ordered.insert(index, ordered[_i])
                                                                                    deref_id += 1
                                                                                    inserts_num += 1
                                                                                    del ordered[_i + 1]
                                                                                    self.debug_derefs(f"size is {len(ordered)}")

                                if found:
                                    break

            # cast_data = self._get_cast_from_deref(deref, f)
            # inserts_num = 0
            # if cast_data is not None:
            #     logging.info("CAST DATA IS NOT NONE")
            #     for t_id in cast_data:
            #         for member in cast_data[t_id]:
            #             if member == Generator.CAST_PTR_NO_MEMBER:
            #                 for oref in deref["offsetrefs"]:
            #                     if "cast" in oref and oref["kind"] == "callref":
            #                         # get the related call order
            #                         ords = f["call_info"][oref["id"]]["ord"]
            #                         if not isinstance(ords, list):
            #                             ords = [ ords ]

            #                         for o in ords:
            #                             found = False
            #                             if o > deref_id:
            #                                 logging.info("processing ords...")
            #                                 # seems like we've found a call with order 
            #                                 # greater than our cast -> let's move it
            #                                 for i in range(len(ordered)):
            #                                     if ordered[i]["id"] == o:
            #                                         # that is our function call                                                
            #                                         diff = i - index
            #                                         logging.info(f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
            #                                         ordered[i]["id"] -= diff
            #                                         ordered.insert(index, ordered[i])
            #                                         deref_id += 1
            #                                         inserts_num += 1
            #                                         del ordered[i + 1]
            #                                         # we have to update the ids of items that go after the inserted one
            #                                         # for j in range(index + 1, len(ordered)):
            #                                         #     ordered[j]["id"] += 1
            #                                         logging.info(f"size is {len(ordered)}")
            #                                         found = True

            #                                 break
            #                             if found:
            #                                 break

            #                         # cool, we have moved the call to it's right place,
            #                         # but we still have to handle the call's params: most likely
            #                         # as their related call they are also located past the cast deref
            #                         # first let's get their ids:
            #                         args = f["call_info"][oref["id"]]["args"]
            #                         # args is a list of ids in our derefs table
                                    
            #                         for _deref_id in args:
            #                             logging.info("handling args")
            #                             deref_obj = f["derefs"][_deref_id]
            #                             ords = deref_obj["ord"]

            #                             for o in ords:
            #                                 found = False
            #                                 if o > deref_id:
            #                                     for i in range(len(ordered)):
            #                                         if ordered[i]["id"] == o:
            #                                             diff = i - index
            #                                             logging.info(f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
            #                                             ordered[i]["id"] -= diff
            #                                             ordered.insert(index, ordered[i])
            #                                             deref_id += 1
            #                                             inserts_num += 1
            #                                             del ordered[i + 1]
            #                                             # # we have to update the ids of the items that go after the inserted one
            #                                             # for j in range(index + 1, len(ordered)):
            #                                             #     ordered[j]["id"] += 1
            #                                             logging.info(f"size is {len(ordered)}")
            #                                             found = True
            #                                     break
            #                                 if found:
            #                                     break
            index += inserts_num
            index += 1
        self.debug_derefs("PROCESSING MEMBERS")
        # one more reordering pass: if we have an offsetref item with kind member, make sure that 
        # it goes before the cotaining dereference
        index = 0 
        while index < len(ordered):
            item = ordered[index]

            if item["type"] == CALL:
                index += 1 
                continue
               
            deref = item["obj"]
            deref_id = int(item["id"])
            if "offsetrefs" in deref:
                for oref in deref["offsetrefs"]:
                    if oref["kind"] == "member":
                        # we have found an offsetref that relates to member
                        dst_id = oref["id"]
                        # getting the deref the member oref relates to
                        dst_deref = f["derefs"][dst_id]

                        # now we need to make sure that dst_deref is located in the trace
                        # before this deref

                        ords = dst_deref["ord"]
                        for o in ords:
                            found = False
                            if o > deref_id:
                                for i  in range(len(ordered)):
                                    if ordered[i]["id"] == o:
                                        diff = i - index
                                        self.debug_derefs(f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
                                        ordered[i]["id"] -= diff
                                        ordered.insert(index, ordered[i])
                                        deref_id += 1
                                        inserts_num += 1
                                        del ordered[i + 1]
                                        found = True
                                break
                            if found:
                                break
            index += inserts_num
            index += 1

        # logging.info("PROCESSING OFFSETOFFS")
        # # one more reordering pass: if we have an offsetref item with kind offsetof, make sure that 
        # # it goes before the cotaining dereference
        # index = 0 
        # while index < len(ordered):
        #     item = ordered[index]

        #     if item["type"] == CALL:
        #         index += 1 
        #         continue
               
        #     deref = item["obj"]
        #     deref_id = int(item["id"])
        #     if "offsetrefs" in deref:
        #         for oref in deref["offsetrefs"]:
        #             if oref["kind"] == "offsetof":
        #                 # we have found an offsetref that relates to member
        #                 dst_id = oref["id"]
        #                 # getting the deref the member oref relates to
        #                 dst_deref = f["derefs"][dst_id]

        #                 # now we need to make sure that dst_deref is located in the trace
        #                 # before this deref

        #                 ords = dst_deref["ord"]
        #                 for o in ords:
        #                     found = False
        #                     if o > deref_id:
        #                         for i  in range(len(ordered)):
        #                             if ordered[i]["id"] == o:
        #                                 diff = i - index
        #                                 logging.info(f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
        #                                 ordered[i]["id"] -= diff
        #                                 ordered.insert(index, ordered[i])
        #                                 deref_id += 1
        #                                 inserts_num += 1
        #                                 del ordered[i + 1]
        #                                 found = True
        #                         break
        #                     if found:
        #                         break
        #     index += inserts_num
        #     index += 1


        logging.debug(f"ordered trace is {ordered}")

        
        for i in range(len(ordered)):
            item = ordered[i]
            if item["type"] == DEREF:
                derefs_trace.append((item["obj"], f))
            elif item["type"] == CALL:
                _f_id = item["obj"]
                _functions = set(functions)
                if f_id in _functions:
                     # mark that we processed the current function already
                     _functions.remove(f_id)
                if _f_id in self.trace_cache:
                    derefs_trace += self.trace_cache[_f_id]
                else:
                    ftrace = self._collect_derefs_trace(_f_id, _functions)
                    self.trace_cache[_f_id] = ftrace
                    derefs_trace += ftrace

        logging.info(f"Collected trace for function {f['name']} is")
        for obj, f in derefs_trace:
            self.debug_derefs(f"{f['id']} : {obj}")

        return derefs_trace

    # -------------------------------------------------------------------------

    def debug_derefs(self, msg):
        if self._debug_derefs:
            logging.info(msg)

    def _match_obj_to_type(self, t_id, objects, adjust_recfwd = True):
        self.debug_derefs(f"matching object to type {t_id}")
        matched_objs = []

        #return matched_objs
        for obj in objects:

            _active_tid = obj.t_id
            _t_id = t_id
            
            if obj.is_pointer:
                _active_tid = self._get_real_type(_active_tid)
                _t_id = self._get_real_type(t_id)

            _active_type = self.typemap[_active_tid]
            _active_type_recfw = False
            if _active_type["class"] == "record_forward":
                _active_type_recfw = True
            
            base_type = self.typemap[_t_id]
            base_type_recfwd = False
            if base_type["class"] == "record_forward":
                base_type_recfwd = True


            
            if t_id == obj.t_id or _t_id == _active_tid:
                matched_objs.append(obj)
            elif t_id in self.dup_types and obj.t_id in self.dup_types[t_id]:
                matched_objs.append(obj)
            elif _t_id in self.dup_types and _active_tid in self.dup_types[_t_id]:
                matched_objs.append(obj)
            elif (base_type_recfwd or _active_type_recfw) and (base_type["str"] == _active_type["str"]):
                # we assume that we came across a record forward
                matched_objs.append(obj)
            elif not self._is_void_ptr(base_type) and base_type["str"] != "void": # we want to avoid matching void* in historic casts
                prev_cast_found = False
                
                for _prev_t_id, _original_tid, _is_pointer in obj.cast_types:
                    self.debug_derefs(f"Checking cast history {_prev_t_id} {_original_tid} {_is_pointer}")
                    if _t_id == _prev_t_id or _t_id == _original_tid or t_id == _prev_t_id or t_id == _original_tid:
                        prev_cast_found = True
                        break
                    _prev_type = self.typemap[_prev_t_id]
                    _original_type = self.typemap[_original_tid]
                    _prev_type_recfw = False
                    _original_type_recfwd = False
                    if _prev_type["class"] == "record_forward":
                        _prev_type_recfw = True
                    if _original_type["class"] == "record_forward":
                        _original_type_recfwd = True
                    if (base_type_recfwd or _prev_type_recfw or _original_type_recfwd) and (base_type["str"] == _prev_type["str"] or base_type["str"] == _original_type["str"]):
                        prev_cast_found = True
                        break

                if prev_cast_found:
                    matched_objs.append(obj)

        
        if adjust_recfwd and len(matched_objs) == 1:
            # we have exactly one match
            obj = matched_objs[0]
            _t_id = t_id
            _obj_id = obj.t_id
            if obj.is_pointer:
                _t_id = self._get_real_type(t_id)
                _obj_id = self._get_real_type(obj.t_id)
            base_type = self.typemap[_t_id]
            obj_type = self.typemap[_obj_id]
            if base_type["class"] == "record" and obj_type["class"] == "record_forward":
                # We initially created this object as a record forward type but now
                # we found the corresponding record for it -> let's update the data in the object
                self.debug_derefs(f"Updating object type from record fwd to record {obj.t_id} -> {t_id}")
                for k in obj.used_members.keys():
                    if k == obj.t_id:
                        obj.used_members[t_id] = obj.used_members[k]
                obj.t_id = t_id
                obj.original_tid = t_id
                   
        return matched_objs

    # starting from the function f_id, collect a trace of all derefs in a DFS-like manner
    # the collected trace is then used to reason about possible casts and uses of types
    # f_id: id of a function we start the trace analysis from
    # functions: a set of functions within which we are processing the trace
    # by default we will process all argument types of the specified function
    # tids: an optional list of types we will be processing (this can be useful if we wish
    # to include global types in the analysis)
    def _parse_derefs_trace(self, f_id, functions, tids=None):    
        # before we can start reasoning we have to collect the trace 

        trace = self._collect_derefs_trace(f_id, functions)

        # we will now perform an analysis of the collected derefs trace for each of
        # the function parameter types
        
        # first, let's get the types
        f = self.fnidmap[f_id]
        arg_tids = f["types"][1:] # types[0] is a return type of the function
        self.debug_derefs(f"processing derefs for function {f['name']}, trace size is {len(trace)}")
        if tids != None:
            for t_id in tids:
                arg_tids.append(t_id)

        active_object = None
        typeuse_objects = []
        ret_val = []
        
        base_obj = None
        for t_id in arg_tids:
            # for a given type we are interested in all casts and offsetof uses
            # what we want to try to learn here is whether the type is used as such or 
            # is casted to another type or is a member of another type (offsetof operator)

            # let's create the first TypeUse for the t_id
            base_obj = TypeUse(self._get_real_type(t_id), t_id, self.typemap[t_id]["class"] == "pointer")
            typeuse_objects = []
            typeuse_objects.append(base_obj)
            base_obj.name = self._get_typename_from_type(self.typemap[base_obj.t_id])
            logging.info(f"Generated TypeUse {base_obj}")      
        
            active_object = base_obj

            for (deref, f) in trace:
                self.debug_derefs(f"Deref is {deref}")
               
                cast_data = self._get_cast_from_deref(deref, f)
                if cast_data is not None:
                    self.debug_derefs(f"cast data is {cast_data}")
                    #current_tid = active_object.t_id
                    for current_tid in cast_data: # we only check if the current object was casted
                        for member in cast_data[current_tid]:
                            _current_tid = current_tid
                            _active_tid  = active_object.t_id
                            if active_object.is_pointer:
                                _current_tid = self._get_real_type(_current_tid)
                            
                            if member == Generator.CAST_PTR_NO_MEMBER:
                                if current_tid != active_object.t_id and _current_tid != _active_tid:
                                    if current_tid in self.dup_types and active_object.t_id in self.dup_types[current_tid]:
                                        self.debug_derefs("dup")
                                        pass
                                    elif _current_tid in self.dup_types and _active_tid in self.dup_types[_current_tid]:
                                        self.debug_derefs("dup")
                                        pass
                                    else:
                                        other_objs = self._match_obj_to_type(current_tid, typeuse_objects)
                                        if len(other_objs) == 1:
                                            self.debug_derefs(f"Active object change detected: from {active_object.id} to {other_objs[0].id}")
                                            active_object = other_objs[0]
                                        else:
                                            self.debug_derefs(f"Active object id is {active_object.t_id} {_active_tid}, and id is {current_tid} {_current_tid}")
                                            continue
                                # the type is casted directly, i.e. without member dereference
                                casted_tid = cast_data[current_tid][member][0]

                                if active_object.t_id != casted_tid:
                                    active_type = self.typemap[self._get_real_type(active_object.t_id)]
                                    active_type = self._get_typedef_dst(active_type)                                    
                                    casted_type = self.typemap[self._get_real_type(casted_tid)]
                                    casted_type = self._get_typedef_dst(casted_type)
                                    struct_types = [ "record", "record_forward" ]
                                    if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                        self.debug_derefs("skipping cast of structural type to non-structural type")
                                    else:
                                        self.debug_derefs("Adding to casted types")
                                        active_object.cast_types.append((active_object.t_id, active_object.original_tid, active_object.is_pointer))
                                        # update the active type of the object
                                        active_object.t_id = casted_tid
                                        active_object.original_tid = casted_tid
                                        if self.typemap[casted_tid]["class"] == "pointer":                                        
                                            active_object.is_pointer = True
                                        else:
                                            active_object.is_pointer = False
                                        active_object.name = self._get_typename_from_type(self.typemap[active_object.t_id])
                                else:
                                    self.debug_derefs("skipping cast due to type mismatch")
                                    
                            else:
                                # first we take the member of the type and then we cast
                                # when members are involved in casts, cast expression happens before member
                                # expression
                                # this is not the order we would like to have, so we need to process that
                                # case separately
                                # The cast type doesn't refer to the the current object type but to it's 
                                # member that is retrieved via the member expression (which is comming 
                                # afterwards in the trace)
                                # we handle this in the _collect_derefs_trace function in which we 
                                # reorder the trace such that member expressions come before casts
                                # if the reordering works correctly we should see that the type of
                                # an active object is the same as the type of the casted member
                                src_type = self.typemap[current_tid]
                                member_tid = src_type["refs"][member]
                                _member_tid = member_tid
                                if active_object.is_pointer:
                                    _member_tid = self._get_real_type(member_tid)
                                                                
                                if active_object.t_id == member_tid or _active_tid == _member_tid:
                                    casted_tid = cast_data[current_tid][member][0]
                                    active_type = self.typemap[self._get_real_type(active_object.t_id)]
                                    active_type = self._get_typedef_dst(active_type)                                    
                                    casted_type = self.typemap[self._get_real_type(casted_tid)]
                                    casted_type = self._get_typedef_dst(casted_type)
                                    struct_types = [ "record", "record_forward" ]
                                    if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                        self.debug_derefs("skipping cast of structural type to non-structural type")
                                    else:
                                        self.debug_derefs("adding to casts")
                                        active_object.cast_types.append((active_object.t_id, active_object.original_tid, active_object.is_pointer))
                                        active_object.t_id = casted_tid
                                        active_object.original_tid = casted_tid
                                        if self.typemap[casted_tid]["class"] == "pointer":                                        
                                            active_object.is_pointer = True
                                        else:
                                            active_object.is_pointer = False
                                        active_object.name = self._get_typename_from_type(self.typemap[active_object.t_id])
                                else:
                                    self.debug_derefs("skipping cast due to type mismatch")
                else:
                    offsetof_data = self._get_offsetof_from_deref(deref)
                    if offsetof_data is not None:
                        # first, let's check if we don't have the containing TypeUse object already
                        self.debug_derefs(f"deref is {deref}")
                        
                        member_no = deref["member"][-1]                        
                        base_tid = self.typemap[deref["type"][-1]]["refs"][member_no] # type[0] is the dst type
                        dst_tid = deref["type"][0]

                        _base_tid = base_tid
                        _active_tid = active_object.t_id
                        if active_object.is_pointer:
                            _active_tid = self._get_real_type(_active_tid)

                        if base_tid != active_object.t_id and _base_tid != _active_tid:
                            if base_tid in self.dup_types and active_object.t_id in self.dup_types[base_tid]:
                                self.debug_derefs("dup")
                                pass
                            elif _base_tid in self.dup_types and _active_tid in self.dup_types[_base_tid]:
                                self.debug_derefs("dup")
                                pass
                            else:
                                other_objs = self._match_obj_to_type(base_tid, typeuse_objects)
                                if len(other_objs) == 1:
                                    self.debug_derefs(f"Active object change detected: from {active_object.id} to {other_objs[0].id}")
                                    active_object = other_objs[0]
                                else:
                                    continue
                        found = False
                        for types, members, obj in active_object.offsetof_types:
                            if types == deref["type"] and members == deref["member"]:
                                # we already have that object
                                self.debug_derefs(f"Active object changed from {active_object.id} to {obj.id}")
                                active_object = obj
                                found = True
                                break
                        if not found:
                            # we need to allocate new TypeUse object for the destination
                            # type of the offsetof operator
                            self.debug_derefs("Creating new offsetof object")
                            new_object = TypeUse(self._get_real_type(dst_tid), dst_tid, True) # we a assume that we use offsetof to
                                                                                              # get a pointer
                            typeuse_objects.append(new_object)
                            new_object.name = self._get_typename_from_type(self.typemap[new_object.t_id])
                            self.debug_derefs(f"Generated TypeUse {new_object}")
                            active_object.offsetof_types.append((deref["type"], deref["member"], new_object))
                            new_object.contained_types.append((deref["type"], deref["member"], active_object))
                            # change active object
                            self.debug_derefs(f"Active object changed from {active_object.id} to {new_object.id}")
                            active_object = new_object
                        else:
                            self.debug_derefs("Using existing offsetof object")
                    else:
                        member_data, access_order = self._get_member_access_from_deref(deref)
                        
                        if member_data:
                            self.debug_derefs("Member access is not none")
                        else:
                            self.debug_derefs("Member access is none")
                        if member_data is not None:

                            # check if we refer to the current active object !
                            first_tid = member_data[access_order[0]]["id"]

                            _first_tid = first_tid
                            _active_tid = active_object.t_id
                            if active_object.is_pointer:
                                _first_tid = self._get_real_type(_first_tid)
                                _active_tid = self._get_real_type(_active_tid)
                            if first_tid != active_object.t_id and _first_tid != _active_tid:
                                if first_tid in self.dup_types and active_object.t_id in self.dup_types[first_tid]:
                                    self.debug_derefs("dup")
                                    pass
                                elif _first_tid in self.dup_types and _active_tid in self.dup_types[_first_tid]:
                                    self.debug_derefs("dup")                                     
                                    pass
                                else:
                                    prev_cast_found = False
                                    for _t_id, _original_tid, _is_pointer in active_object.cast_types:
                                        self.debug_derefs(f"Checking cast history {_t_id} {_original_tid} {_is_pointer}")
                                        if _first_tid == _t_id or _first_tid == _original_tid or first_tid == _t_id or first_tid == _original_tid:
                                            prev_cast_found = True
                                            break
                                    if prev_cast_found:
                                        self.debug_derefs("Phew, we've found the previous cast that matches the type id")
                                    else:
                                        # one last check would be to see if there is a single type match among the active
                                        # objects -> this trick is aimed at helping in a situation where the sequence of 
                                        # dereferences is non-monotonic - e.g. we get a pointer, store it in a variable
                                        # then we use another pointer and get back to the first one; 
                                        # a heavier approach to this problem would be to perform some sort of data flow or variable
                                        # name tracking; what we do here is to assume that if we have a single matching type, it's probably
                                        # one of the objects we already created

                                        other_objs = self._match_obj_to_type(first_tid, typeuse_objects)
                                        if len(other_objs) == 1:
                                            self.debug_derefs(f"Active object change detected: from {active_object.id} to {other_objs[0].id}")
                                            active_object = other_objs[0]
                                            
                                        else:
                                            self.debug_derefs(f"Active object id is {active_object.t_id} {_active_tid}, and id is {first_tid} {_first_tid}")
                                            continue
                            self.debug_derefs(f"access order is {access_order}")
                            for t_id in access_order:
                                t = member_data[t_id]
                                for i in range(len(t["usedrefs"])):
                                    member_tid = t["usedrefs"][i]
                                    if member_tid != -1:
                                        member_no = i
                                        active_tid = active_object.t_id
                                        # check if the member is already in our used members data:
                                        if active_tid in active_object.used_members and member_no in active_object.used_members[active_tid]:
                                            # yes -> we pick the existing object
                                            self.debug_derefs(f"Active object changed from {active_object.id} to {active_object.used_members[active_tid][member_no].id}")
                                            active_object = active_object.used_members[active_tid][member_no]
                                            self.debug_derefs("Member detected in used members")
                                        else:
                                            # check if the member is present in the contained types:
                                            # if yes, use the existing object
                                            offsetof_found = False
                                            for types, members, obj in active_object.contained_types:
                                                if types[-1] == t_id and member_no == members[-1]:
                                                    self.debug_derefs("This member was used in a prior offsetof")                                                    
                                                    if active_tid not in active_object.used_members:
                                                        active_object.used_members[active_tid] = {}
                                                    active_object.used_members[active_tid][member_no] = obj
                                                    self.debug_derefs(f"Active object changed from {active_object.id} to {obj.id}")
                                                    active_object = obj               
                                                    offsetof_found = True
                                            if offsetof_found:
                                                continue
                                            self.debug_derefs("Creating new member")
                                            # no -> we create a new object
                                            new_object = TypeUse(self._get_real_type(member_tid), member_tid, self.typemap[member_tid]["class"] == "pointer")
                                            typeuse_objects.append(new_object)
                                            new_object.name = self._get_typename_from_type(self.typemap[new_object.t_id])
                                            self.debug_derefs(f"Generated TypeUse {new_object}")

                                            active_type = self.typemap[active_tid]
                                            obj_type = self.typemap[t_id]
                                            if active_type["class"] == "record_forward" and active_tid != t_id and obj_type["class"] == "record":
                                                self.debug_derefs(f"Updating object type from record fwd to record {active_tid} -> {t_id}")
                                                for k in active_object.used_members.keys():
                                                    if k == obj.t_id:
                                                        active_object.used_members[t_id] = active_object.used_members[k]
                                                active_object.t_id = t_id
                                                active_object.original_tid = t_id
                                                 

                                            # take a note that the member is used
                                            if active_object.t_id not in active_object.used_members:
                                                active_object.used_members[active_object.t_id] = {}
                                            active_object.used_members[active_object.t_id][member_no] = new_object
                                            # update active object
                                            self.debug_derefs(f"Active object changed from {active_object.id} to {new_object.id}")
                                            active_object = new_object
            ret_val.append((t_id, base_obj))


        return ret_val

    
    # -------------------------------------------------------------------------

    # return True if the type if is void*, False otherwise
    def _is_void_ptr(self, t):
        if t is None:
            logging.error(f"Type {t} not found")
            return False
        t = self._get_typedef_dst(t)

        if t["class"] != "pointer":
            return False

        # we know it's a pointer
        dst_tid = t["refs"][0]
        dst_t = self.typemap[dst_tid]
        if dst_t is None:
            logging.error(f"Type {dst_tid} not found")
            return False

        if dst_t["class"] != "builtin":
            return False

        if dst_t["str"] == "void":
            return True

        return False

    # -------------------------------------------------------------------------

    # return True if a struct member is in use, False otherwise
    def _is_member_in_use(self, type, type_name, member_idx):
        if type["class"] != "record":
            return True

        is_in_use = True
        field_name = type["refnames"][member_idx]

        # let's check if the field is used
        if type['id'] not in self.used_types_data:
            is_in_use = False
        elif "usedrefs" in type: 
            # TODO: remove size check
            if member_idx < len(type["usedrefs"]) and -1 == type["usedrefs"][member_idx]:
                if self.debug_vars_init:
                    logging.info(
                        f"Detected that field {field_name} in {type_name} is not used")
                is_in_use = False
            if member_idx >= len(type["usedrefs"]):
                logging.warning(
                    f"Unable to check if {field_name} is used or not")
        
        return is_in_use

    # -------------------------------------------------------------------------

    def _get_callref_from_deref(self, deref):
        if deref["kind"] == "offsetof":
            return False
        if "offsetrefs" in deref:
            for oref in deref["offsetrefs"]:
                if oref["kind"] == "callref":
                    return True

        return False

    # -------------------------------------------------------------------------

    # If there is a cast in the deref, return the associated data,
    # return None if no cast has been found
    def _get_cast_from_deref(self, deref, f):
        if deref["kind"] == "offsetof":
           return None
        cast_tid = -1
        ret_val = None

        # TODO: implement "kind": "return" -> in that case we don't need to have
        # cast in the offsetrefs
        logging.debug(f"get cast from deref: {deref}")

        # first, check if we are not doing pointer arithmetic
        if deref["kind"] == "assign" and deref["offset"] != 21:
            self.debug_derefs(f"skipping deref associated with arithmetic {deref}")

        elif "offsetrefs" in deref:
            for oref in deref["offsetrefs"]:
                src_tid = -1
                src_root_tid = -1
                src_member = -1
                dst_deref = None
                if "cast" in oref:

                    # get the type we are casting to
                    cast_tid = oref["cast"]
                    cast_type = self.typemap[cast_tid]
                    id = oref["id"]

                    # get the type we are casting from
                    if oref["kind"] == "unary":
                        self.debug_derefs(
                            f"Unsupported deref type {oref['kind']}")
                        continue

                    elif oref["kind"] == "array":
                        array_deref = f["derefs"][oref['id']]
                        array_found = False
                        if array_deref["kind"] == "array":
                            for _oref in array_deref["offsetrefs"]:
                                if _oref["kind"] == "member":
                                    dst_deref = f["derefs"][_oref["id"]]
                                    array_found = True
                        if not array_found:
                            self.debug_derefs(
                                f"Unsupported deref type {oref['kind']}")
                            continue

                    elif oref["kind"] == "member":
                        if id >= len(f["derefs"]):
                            logging.error(
                                f"id {id} larger than the derefs size")
                            # sys.exit(1) <- uncomment for testing
                            continue
                        dst_deref = f["derefs"][id]
                        logging.debug(f"dst deref is {dst_deref}")
                 
                    elif oref["kind"] == "assign":
                        self.debug_derefs(
                            f"Unsupported deref type {oref['kind']}")
                        continue
                    
                    elif oref["kind"] == "function":
                        self.debug_derefs(
                            f"Unsupported deref type {oref['kind']}")
                        continue

                    elif oref["kind"] == "global":
                        self.debug_derefs(
                            f"Unsupported deref type {oref['kind']}")
                        continue

                    elif oref["kind"] == "local":
                        src_tid = f["locals"][oref["id"]]["type"]
                        #logging.error(
                        #    f"Unsupported deref type {oref['kind']}")
                        #continue

                    elif oref["kind"] == "parm":
                        dst_deref = f["locals"][id]

                    elif oref["kind"] == "callref":
                        # this happens when a return value of a function is casted to other type
                        dst_deref = None
                        # the source type in this case is the return type of the function
                        call_id = f["calls"][oref["id"]]
                        call = self.fnidmap[call_id]
                        if call is None:
                            self.debug_derefs(
                                f"Call not found in functions")
                            continue
                        src_tid = call["types"][0]

                        if deref["kind"] == "return": 
                            cast_tid = f["types"][0] # return type goes first
                            cast_type = self.typemap[cast_tid]
                            src_tid = oref["cast"]
                        elif deref["kind"] == "init":
                            inited = deref["offsetrefs"][0] # let's assume that the first oref is the 
                                                       # value that is being initialized
                            if inited["kind"] == "local":
                                cast_tid = f["locals"][inited["id"]]["type"]
                                cast_type = self.typemap[cast_tid]
                    else:
                        self.debug_derefs(
                            f"Unsupported deref type {oref['kind']}")
                        continue

                    if dst_deref is not None and "type" not in dst_deref:
                        self.debug_derefs(
                            f"Type not found in deref {dst_deref}")
                        # sys.exit(1) <- uncomment for testing
                        continue
                    src_root_tid = src_tid
                    if dst_deref is not None:
                        if isinstance(dst_deref["type"], list):
                            # kind == member
                            # Note: in the easy case we just derefernce a single member,
                            # but this could as well be something like a = b->c->d, so we need to
                            # get to the final member in the dereference "chain"

                            src_tid = dst_deref["type"][-1]
                            src_member = dst_deref["member"][-1]
                            src_root_tid = src_tid
                            src_tid = self._get_real_type(src_tid)
                        else:
                            # kind == parm
                            src_root_tid = dst_deref["type"]
                            src_tid = self._get_real_type(dst_deref["type"])

                    src_type = self.typemap[src_tid]
                    src_root_type = src_type
                    # member is only meaningful for records
                    if src_type["class"] == "record":
                        #logging.info(f"src_tid = {src_tid} src_member = {src_member} dst_deref = {dst_deref} deref = {deref}")
                        if src_member != -1:
                            src_member_tid = src_type["refs"][src_member]
                            src_type = self.typemap[src_member_tid]
                        else:
                            src_member = Generator.CAST_PTR_NO_MEMBER
                    else:
                        src_member = Generator.CAST_PTR_NO_MEMBER

                    # let's check if the source and destination type don't have the same root:
                    dst_root = self._get_real_type(cast_tid)
                    if src_member == Generator.CAST_PTR_NO_MEMBER:
                        if src_tid in self.dup_types:          
                            found = False                          
                            for t_id in self.dup_types[src_tid]:
                                if t_id == dst_root:
                                    found = True
                                    break
                            if found:
                                continue
                        elif src_tid == dst_root:
                            continue
                    else:
                        src_root = self._get_real_type(src_member_tid)
                        if src_root in self.dup_types:
                            found = False
                            for t_id in self.dup_types[src_root]:
                                if t_id == dst_root:
                                    found = True
                                    break
                            if found:
                                continue
                        elif src_root == dst_root:
                            continue

                    if src_tid != cast_tid:
                        # last checks: see if we are not dealing with typedefs pointing to the same type:
                        if src_member == Generator.CAST_PTR_NO_MEMBER:
                            src_no_typedef = self._get_typedef_dst(self.typemap[src_root_tid])["id"]
                        else:
                            src_no_typedef = self._get_typedef_dst(self.typemap[src_member_tid])["id"]
                        dst_no_typedef = self._get_typedef_dst(self.typemap[cast_tid])["id"]
                        if src_no_typedef == dst_no_typedef:
                            self.debug_derefs(f"source {src_tid} same as dst type {cast_tid}")
                            #sys.exit(1)
                            continue
                        # see if the size of source and dst type matches
                        # caveat: there could be a cast like this : int* ptr = (int*)&s->member
                        # member coult be u16 but its address used to process data as int - we currently
                        # don't support that scheme -> TBD
                        #src_size = self.typemap[src_no_typedef]["size"]
                        src_size = self.typemap[self._get_typedef_dst(self.typemap[src_root_tid])["id"]]["size"]

                        dst_size = self.typemap[dst_no_typedef]["size"]
                        if src_size != dst_size:
                            self.debug_derefs(f"Source {src_root_tid}:{src_size} and dst {dst_no_typedef}:{dst_size} type size mismatch - skipping cast")
                            #sys.exit(1)
                            continue

 
                        if not self._is_void_ptr(cast_type) or deref["kind"] == "return":
                            # in addition to void* casted to other types, we are also interested to know
                            # if non-void pointer types are casted

                            store_tid = -1
                            if src_root_type["class"] == "record" or src_root_type["class"] == "record_forward":
                                store_tid = src_tid
                            else:
                                store_tid = src_root_tid

                            if ret_val is None:
                                ret_val = {}
                            if store_tid not in ret_val:
                                ret_val[store_tid] = {}
                            if src_member not in ret_val[store_tid]:
                                ret_val[store_tid][src_member] = []
                            if cast_tid not in ret_val[store_tid][src_member]:
                                ret_val[store_tid][src_member].append(cast_tid)                        
                            
                                
        # take care of the duplicates
        if ret_val is not None:
            for src_tid in list(ret_val.keys()):
                if src_tid in self.dup_types:
                    dups = self.dup_types[src_tid]
                    for dup in dups:
                        if dup not in ret_val:
                            ret_val[dup] = copy.deepcopy(ret_val[src_tid])

        return ret_val

    # -------------------------------------------------------------------------

    # If there is an offsetof expression in the deref, return the associated data,
    # return None if no offsetof has been found
    def _get_offsetof_from_deref(self, deref):
        
        if deref["kind"] != "offsetof":
            return None

        # it's a heuristic, but let's assume that when we use offsetof we actually mean to get from one type to another
        # in other words, let's treat it as a form of type cast
        
        dst_tid = deref["type"][0]

        # we are only interested in the last member, last type
        member_no = deref["member"][-1]
        src_tid = self.typemap[deref["type"][-1]]["refs"][member_no]

        ret_val = {}
        ret_val[src_tid] = [ (deref["type"], deref["member"]) ]

        # take care of the duplicates:
        if src_tid in self.dup_types:
            dups = self.dup_types[src_tid]

            for dup in dups:
                if dup not in ret_val:
                    ret_val[dup] = copy.deepcopy(ret_val[src_tid])

        return ret_val

    # -------------------------------------------------------------------------
   
    # if there is a member access in the deref, return the associated data,
    # return None if no member access has been found
    def _get_member_access_from_deref(self, deref):
        if deref["kind"] != "member":
            return None, None

        # filter out accesses by address as they distort derefs trace parsing
        for oref in deref["offsetrefs"]:
            if oref["kind"] == "address":
                self.debug_derefs("Ignoring member access on address")
                return None, None

        ret_val = {}     
        access_order = []
        for mi in range(len(deref["access"])):
            t_id = deref["type"][mi]                
            t = self.typemap[t_id]
            if deref["access"][mi] == 1:
                t_id = self._get_typedef_dst(t)['id']
                t_id = self._get_real_type(t_id)
                t = self.typemap[t_id]
            t = self._get_typedef_dst(t)
            t_id = t["id"]
            item = None
            if t_id not in ret_val:                    
                ret_val[t_id] = copy.deepcopy(t) # we create a deep copy in order to avoid
                                                            # interfering with the db cache
                item = ret_val[t_id]
                # we will update the "usedrefs information"
                for i in range(len(item["usedrefs"])):
                    item["usedrefs"][i] = -1
                #logging.debug(f"processing deref {d}, t_id={t_id}, item={item}")
            else:
                item = ret_val[t_id]
            
            access_order.append(t_id)
            
            # let's make a note that the member is used
            member_id = deref["member"][mi]
            t_id = t["refs"][member_id]

            if item["usedrefs"][member_id] != -1 and item["usedrefs"][member_id] != t_id:
                logging.error(f"This member had a different id: t_id={t_id}, member_id={member_id}, prev={item['usedrefs'][member_id]}, curr={t_id}")
                shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")
                sys.exit(1)
            
            item["usedrefs"][member_id] = t_id
            
            # if the used member is a record itself, let's add it to the map in order
            # to mark that the type is used (this can help if we have a record type without any member usages)
            t_id = self._get_real_type(t_id)
            t = self.typemap[t_id]
            t = self._get_typedef_dst(t)
            t_id = t["id"]
                            
            if t["class"] == "record" and t_id not in ret_val:                    
                ret_val[t_id] = copy.deepcopy(t) # we create a deep copy in order to avoid
                                                            # interfering with the db cache
                item = ret_val[t_id]
                # we will update the "usedrefs information"
                for i in range(len(item["usedrefs"])):
                    item["usedrefs"][i] = -1

        # merge data from type dups
        for t_id in list(ret_val.keys()):
            if t_id in self.dup_types:
                t = ret_val[t_id]
                dups = self.dup_types[t_id]

                for dup in dups:
                    if dup in ret_val:
                        t2 = ret_val[dup]
                        for i in range(len(t["usedrefs"])):
                            if (t["usedrefs"][i] != -1 and t2["usedrefs"][i] == 1) or (t["usedrefs"][i] == -1 and t2["usedrefs"][i] != 1):
                                if t["usedrefs"][i] == -1:
                                    t["usedrefs"][i] = t2["usedrefs"][i]
                                else:
                                    t2["usedrefs"][i] = t["usedrefs"][i]

        # take type dups into account
        for t_id in list(ret_val.keys()):
            if t_id in self.dup_types:
                dups = self.dup_types[t_id]
                for dup in dups:
                    if dup not in ret_val:
                        ret_val[dup] = copy.deepcopy(ret_val[t_id])

        return ret_val, access_order

    # -------------------------------------------------------------------------

    # the idea behind this helper function is to discover all type casts across pointers
    # by using the dereference information stored in the functions metadata
    # This information can be used, e.g., to find the "real" type behind a void* pointer.
    # It can also be used to detect scenarios in which one type is used as a different type 
    # after a cast (which in turn helps to find which member of that other types are in use in 
    # case of structural types).
    def _discover_casts(self, functions):



        for f_id in functions:

            f = self.fnidmap[f_id]
            if f is None:
                logging.info(f"Function id {f_id} not found among functions")
                continue
            cast_tid = -1

            for deref in f["derefs"]:

                if deref["kind"] != "offsetof": 
                    cast_data = self._get_cast_from_deref(deref, f) 
                    
                
                    if cast_data is None:
                        continue
                    elif deref['expr'].lstrip().startswith('&'):
                        # workaround for a special case:
                        # we have found a cast but the expression in which it was detected
                        # is an address dereference
                        continue

                    for src_tid in cast_data:
                        if src_tid not in self.casted_pointers:
                            self.casted_pointers[src_tid] = cast_data[src_tid]
                        else:
                            for src_member in cast_data[src_tid]:
                                if src_member not in self.casted_pointers[src_tid]:
                                    self.casted_pointers[src_tid][src_member] = cast_data[src_tid][src_member]
                                else:
                                    for cast_tid in cast_data[src_tid][src_member]:
                                        if cast_tid not in self.casted_pointers[src_tid][src_member]:
                                            self.casted_pointers[src_tid][src_member].append(cast_tid)
                else:

                    # we are dealing with the offsetof construct

                    offsetof_data = self._get_offsetof_from_deref(deref)

                    if offsetof_data is None:
                        continue

                    for src_tid in offsetof_data: 
                        if src_tid not in self.offset_pointers:
                            self.offset_pointers[src_tid] = offsetof_data[src_tid]
                        else:
                            for types, members in offsetof_data[src_tid]:
                                found = False
                                for t, m in self.offset_pointers[src_tid]:
                                    if t == types and m == members:
                                        found = True
                                        break
                                if found == False:
                                    self.offset_pointers[src_tid].append( (types, members) )
                    # offsetpointers is a map that links internal types to their containing structures

   
        logging.info(
            f"We discovered the following void pointers cast data {self.casted_pointers}")

    # -------------------------------------------------------------------------

    def _get_used_types_data(self):
        self.used_types_data = {}
        # at this point we know all the functions that are going to be a part of the off-target
        # based on that information let's find out which members of the structural types (records and unions) are used
        # we are going to leverage that information for a smarter, more focused data initialization

        logging.info("Capturing used types information")
        for f_id in self.internal_funcs:
            f = self.fnidmap[f_id]
            if f is None:
                continue # that's a funcdecl or unresolved func (unlikely)

            # we will extract the member usage from the "derefs" data
            if "derefs" not in f:
                continue
                
            for d in f["derefs"]:

                member_data, access_order = self._get_member_access_from_deref(d)
                if member_data is None:
                    continue

                for t_id in member_data:
                    if t_id not in self.used_types_data:
                        self.used_types_data[t_id] = member_data[t_id]
                    else:
                        for i in range(len(member_data[t_id]["usedrefs"])):
                            used = member_data[t_id]["usedrefs"][i]
                            if "usedrefs" not in self.used_types_data[t_id]:
                                logging.error(f"usedrefs not found in type {t_id}")
                            if used != -1:
                                self.used_types_data[t_id]["usedrefs"][i] = used


                

        logging.info(f"Used types data captured, size is {len(self.used_types_data)}")

    # -------------------------------------------------------------------------

    def _debug_print_typeuse_obj(self, obj, visited=None):
        members = []
        if visited is None:
            visited = set()
        if obj in visited:
            return 
        visited.add(obj)
        logging.info(f"Obj: {obj}")

        for _type_id in obj.used_members:
            for member_id in obj.used_members[_type_id]:
                self._debug_print_typeuse_obj(obj.used_members[_type_id][member_id], visited)
        for _type_id, member, _obj in obj.offsetof_types:
            self._debug_print_typeuse_obj(_obj, visited)

    # @entry_points: the list of functions that are called from main
    # NOTE: you can use the original "main" function if you specify it
    # as the only entry point
    def _create_test_driver(self, entry_points, static_functions, all_global_ids):
        logging.info(
            "Creating test driver, entry_points {}".format(entry_points))
        #types = self._get_types_in_funcs(entry_points)

        str = self._get_file_header()
        str += "\n#include \"aot.h\"\n\n"
        #str += Generator.AOT_INCLUDE_MARKER
        str_header, str, name, func_ids, globals_id, types, internal_defs = self._create_src_file(-1, entry_points, all_global_ids, [], static_functions,
                                                                                                  stubs=False, test_driver=True)
        name = "aot.c"
        # types = set()
        # internal_defs = set()
        # types = self._get_types_in_funcs(entry_points, internal_defs, types_only=True)

        # str = self._get_file_header()

        # str += "\n#include \"aot.h\""
        str += "\n#include \"aot_mem_init_lib.h\""
        str += "\n#include \"aot_fuzz_lib.h\""
        str += "\n#include \"aot_log.h\""
        str += "\n#include \"aot_recall.h\""

        if self.afl != 'none':
            str += "\n#include <stdio.h>"

        if self.verify_struct_layout:
            str += "\n\n" + self._load_snippet("verify_layout_decl")
        
        str += "\n\n"
        #str_header = self._get_file_header()

        if self.afl == 'genl_ops':
            # inster genl_ops init snippet
            str += self._load_snippet("genl_ops_init")

        main_start = len(str)

        str += "\n\n/* ----------------------------- */\n" +\
            "/* Main test driver section      */\n" +\
            "/* ----------------------------- */\n" +\
            "int main(int AOT_argc, char* AOT_argv[]) {\n"

        if self.verify_struct_layout:
            str += self._load_snippet("verify_layout")
            str += "\n\n"

        str += "\taot_log_init();\n"

        if self.init:
            str += "\tinit_fuzzing(AOT_argc, AOT_argv);\n"
            str += "\tchar* tmpname = 0;\n"

        known_type_names = set()
        for t_id in types:
            t = self.typemap[t_id]
            if t["class"] == "record":                
                known_type_names.add(t["str"])

        logging.info(f"known type names are {known_type_names}")
        new_types = set()

        if self.init:
            self._get_used_types_data()

            # since we're doing init it will be useful to get the data on all casts
            # of void* variables/members to other types
            # we can then try to generate more precise initialization code for void* members which
            # reflects their true type
            self._discover_casts(self.internal_funcs)

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
            #         g["name"], self.typemap[g["type"]], "", pointers, known_type_names=known_type_names, new_types=new_types, 
            #         entity_name=g['name'], fuse=0)
            #     str += "\t" + tmp_str.replace("\n", "\n\t")

        globalsInit = False
        all_globals = []
        all_global_tids = []
        for g_id in all_global_ids:
            g = self.globalsidmap[g_id]
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

            if self.init:
                ret_val = self._parse_derefs_trace(f_id, self.internal_funcs, tids=additional_tids)
                self.funcs_init_data[f_id] = ret_val


            if self.init and not globalsInit:
                globalsInit = True # globals are initialized on the first entry point

                self.globs_init_data = {}
                i = len(self.fnidmap[f_id]["types"]) - 1 # the number of function args - data beyond args is for globals
                for g_id in all_global_ids:
                    self.globs_init_data[g_id] = self.funcs_init_data[f_id][i]
                    i += 1

                # initialize the globals
                # we'll skip those that have an initialzier or are static (as they cannot be pulled into another file)
                # Note: we may want to skip init if db.json will be generated from off-target; this is due to the fact
                # that the init code introduces references to sturcture members that may not be used otherwise in the code,
                # so we don't want to affect that in the db.json

                str += "\n\t//Global vars init\n"
                static_globals_noinit = set()
                for g in all_globals:
                    if g["hasinit"]:
                        skip_init = True
                        # one more check: sometimes globals are pointers initialized to null
                        g_tid = g["type"]
                        g_t = self.typemap[g_tid]
                        g_t = self._get_typedef_dst(g_t)                        
                        if g_t["class"] == "pointer":
                            initstr = g["init"]
                            if initstr == "((void *)0)":
                                if g['linkage'] == "internal":
                                    logging.info(f"Global {g['name']} has a null initialized and is static -> skipping for now")
                                    continue
                                logging.info(f"Global {g['name']} is a pointer initialized to null -> will generate init")
                                skip_init = False
                        if skip_init:
                            logging.info(
                                f"Global {g['name']} already has an initializer -> skipping")
                            continue
                    elif g["linkage"] == "internal":
                        # no init code for the global + the global is static
                        logging.warning(
                            f"Global {g['name']} lacks initializer, but it's static")
                        static_globals_noinit.add(g["id"])
                        continue
                    pointers = []
                    self.recursion_fuse = 0
                    init_obj = None
                    param_tid, init_obj = self.globs_init_data[g['id']]

                    tmp_str, alloc = self._generate_var_init(
                        g["name"], self.typemap[g["type"]], "", pointers, known_type_names=known_type_names, new_types=new_types, 
                        entity_name=g['name'], fuse=0, init_obj=init_obj)
                    str += "\t" + tmp_str.replace("\n", "\n\t")

                str += "\n" 
                for id in self.fid_to_filename:
                    str += f"\taot_init_globals_file_{id}();\n"

            if self.init:  
                logging.info(f"init data for {f_id}: {ret_val}")
                for _t_id, _init_data in ret_val:
                    #logging.info(f"{_t_id} : {_init_data}") 
                    obj = _init_data
                    self._debug_print_typeuse_obj(obj)
            
        if self.dynamic_init:       
            if self.kflat_img:
                str += "\n\taot_kflat_init(\"%s\");\n"%self.kflat_img
            else:
                str += "\n\taot_kflat_init(\"%s\");\n"%Generator.KFLAT_IMAGE_NAME

        str += "\n\n\t".join([self._generate_function_call(x, static=(x in static_functions), known_type_names=known_type_names, new_types=new_types).replace("\n", "\n\t")
                              for x in entry_points]) + "\n"

        if self.dynamic_init:
            str += "\taot_kflat_fini();\n\n"

        str += "\n    return 0;\n"
        str += " }\n"

        logging.info(f"We have the following new types: {new_types}")
        #internal_defs = set()
        additional_types, _ = self._get_types_recursive(
            new_types, base_types=types, internal_defs=internal_defs)
        additional_types = self._remove_duplicated_types(additional_types)
        self._filter_internal_types(additional_types, internal_defs)

        str_header += "\n// Additional types from casts\n"
        str_header += self._get_type_decls(additional_types)
        tmp_str, failed = self._get_type_defs(additional_types)
        for t_id in tmp_str:
            str_header += tmp_str[t_id]

        tmp = str[:main_start]
        for stub in self.fpointer_stubs:           
            tmp += stub
        str = tmp + str[main_start:]

        if self.init:
            logging.info("We didn't initialize the following static globals:")
            for g_id in static_globals_noinit:
                g = self.globalsidmap[g_id]
                logging.info(f"g['name']")
        for t_id in additional_types:
            types.append(t_id)

        return str_header, str, name, globals_id, types, internal_defs

    
    # -------------------------------------------------------------------------
    ## For a given function F generates code that initializes global function pointer
    ##  with its address
    ## For example for function 'myfun' in file 'kernel/mm/myfile.c' we should get:
    ##  'int (*__pf__kernel__mm__myfile____c__myfun)(void) = myfun;'
    def _get_function_pointer_stub(self, function):

        if "abs_location" in function and len(function["abs_location"].split(":")[0]) > 0:
            loc = function["abs_location"].split(":")[0]
        else:
            loc = os.path.normpath(function["location"].split(":")[0])
        if os.path.isabs(loc):
            if self.source_root is not None and len(self.source_root) > 0:
                loc = loc[len(self.source_root)+1:]
            else:
                assert 0, "Detected absolute location in function location (%s) but the 'source root' parameter is not given"%(function["location"])
        fptr_stub_name = "%s__%s"%(loc.replace("/","__").replace("-","___").replace(".","____"),function["name"])
        self.function_pointer_stubs.add((fptr_stub_name,function["id"]))
        fptr_stub_def = "int (*%s)(void) = (int (*)(void))%s;"%(fptr_stub_name,function["name"])
        if function["id"] in self.lib_funcs_ids:
            self.lib_function_pointer_stubs.add((fptr_stub_def,function["id"]))
        return fptr_stub_def
    # -------------------------------------------------------------------------

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

    def _get_header_guard(self, filename):
        guard = filename.replace(".", "_")
        guard = guard.replace("-", "_")
        guard = f"AOT_{guard}"
        guard = guard.upper()
        ifdefstr = f"#ifndef {guard}\n"
        ifdefstr += f"#define {guard}\n"
        return ifdefstr

    # -------------------------------------------------------------------------

    def _store_item_in_header(self, filename, contents):
        file_path = f"{self.out_dir}/{filename}"
        _str = ""
        if not os.path.isfile(file_path):
            _str += self._get_header_guard(filename) + "\n"
            if filename != Generator.AOT_HEADER:
                _str += f"// Original location of this header: {self.header_to_location[filename]}\n"
            else:
                _str += "#include \"aot_replacements.h\"\n\n"
            _str += "#include \"aot_log.h\"\n\n"
        _str += contents

        with open(f"{self.out_dir}/{filename}", "a+") as file:
            file.write(_str)

    # -------------------------------------------------------------------------

    # store an item in AoT-generated header file
    # item could be a function or a type

    def _map_item_to_header(self, item):
        filename = None
        if "abs_location" in item or "location" in item:
            if "abs_location" in item and len(item["abs_location"]) > 0:                
                loc = item["abs_location"].split(":")[0]
            else:
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

    def _create_static_inline_header(self, function):
        f_id = function["id"]

        filename = self._map_item_to_header(function)
        if filename is None:
            logging.error(
                f"Filename not found for function {function['name']}")
            shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")               
            sys.exit(1)
        self.static_inline_headers[f_id] = filename

        return filename

    # -------------------------------------------------------------------------

    def _filter_internal_types(self, types, internal_defs):
        for t in internal_defs:
            to_check = []
            if t in self.dup_types:
                to_check = self.dup_types[t]  # dup_types[t] contains t too
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
        for tid in self.implicit_types:
            if tid in types:
                types.remove(tid)

    # -------------------------------------------------------------------------

    def _get_type_clash_ifdef(self, t_id, fid):
        ifdef = ""
        ifgenerated = False
        if t_id in self.clash_type_to_file:
            #if fid in self.clash_type_to_file[t_id]:
            # now we know that this file is using a type that clashes with some other type

            for file_id in self.clash_type_to_file[t_id]:
                if len(ifdef) != 0:
                    ifdef += " && "
                ifdef += f"!defined({self._get_file_define(file_id)})"

            if len(ifdef) == 0:
                logging.info(f"ifdef len is 0, t_id is {t_id}")
            else:
                ifdef = f"#if {ifdef}\n"
                ifgenerated = True
            if t_id in self.type_clash_nums:
                ifdef += f"#ifndef CLASH_{self.type_clash_nums[t_id]}\n"
                ifdef += f"#define CLASH_{self.type_clash_nums[t_id]}\n"


        return ifdef, ifgenerated

    # -------------------------------------------------------------------------

    def _get_type_clash_endif(self, t_id, fid, ifgenerated=True):
        endif = ""
        if t_id in self.clash_type_to_file:
            #if fid in self.clash_type_to_file[t_id]:
            if ifgenerated == True:
                endif = "#endif\n"
            if t_id in self.type_clash_nums:
                endif += "#endif\n"

        return endif

    # -------------------------------------------------------------------------

    def _get_global_clash_ifdef(self, g_id, fid):
        ifdef = ""
        if g_id in self.clash_global_to_file:
            #if fid in self.clash_global_to_file[g_id]:
            # now we know that this file is using a global that clashes with some other global

            for file_id in self.clash_global_to_file[g_id]:
                if len(ifdef) != 0:
                    ifdef += " && "
                ifdef += f"!defined({self._get_file_define(file_id)})"
            ifdef = f"#if {ifdef}\n"
            if g_id in self.glob_clash_nums:
                ifdef += f"#ifndef CLASH_{self.glob_clash_nums[g_id]}\n"
                ifdef += f"#define CLASH_{self.glob_clash_nums[g_id]}\n"
        return ifdef

    # -------------------------------------------------------------------------

    def _get_global_clash_endif(self, g_id, fid):
        endif = ""
        if g_id in self.clash_global_to_file:
            #if fid in self.clash_global_to_file[g_id]:
            endif = "#endif\n"
            if g_id in self.glob_clash_nums:
                endif += "#endif\n"

        return endif

    # -------------------------------------------------------------------------

    def _get_func_clash_ifdef(self, f_id, fid):
        ifdef = ""
        if f_id in self.clash_function_to_file:
            #if fid in self.clash_function_to_file[f_id]:
            # now we know that this file is using a function that clashes with some other function

            for file_id in self.clash_function_to_file[f_id]:
                if len(ifdef) != 0:
                    ifdef += " && "
                ifdef += f"!defined({self._get_file_define(file_id)})"
            ifdef = f"#if {ifdef}\n"
            if f_id in self.func_clash_nums:                
                ifdef += f"#ifndef CLASH_{self.func_clash_nums[f_id]}\n"
                ifdef += f"#define CLASH_{self.func_clash_nums[f_id]}\n"

        return ifdef

    # -------------------------------------------------------------------------

    def _get_func_clash_endif(self, f_id, fid):
        endif = ""
        if f_id in self.clash_function_to_file:
            endif = "#endif\n"
        if f_id in self.func_clash_nums:
            endif += "#endif\n"

        return endif

    # -------------------------------------------------------------------------

    def _create_src_file(self, fid, functions, globs, includes, static_funcs, stubs=False, test_driver=False, create_header=False):

        internal_defs = set()
        if stubs is False:
            name = "file_{}.c".format(fid)
        else:
            name = "file_stub_{}.c".format(fid)

        if fid == Generator.AOT_HEADER_ID:
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

            global_types, global_fwd_str, global_defs_str, globals_ids = self._get_global_types(
                functions, globs, [], True, internal_defs, file_id, global_type_decls)

            types = self._get_types_in_funcs(functions, internal_defs)
            logging.debug("File {} contains {} functions and {} types".format(
                name, len(functions), len(types)))

            containing_types = set()
            for t_id in global_types:
                if t_id in internal_defs:
                    logging.error(
                        f"type {t_id} is both inside global types and internal defs")
                    # let's get the containing type
                    if t_id not in self.internal_types:
                        # check if we don't have a type duplicate
                        # what could have happened is that we have a duplicate types: e.g. one constant
                        # the other not, and only one of them has related containig type such as typedef
                        # in that case we need to find that typedef's id
                        dups = self.dup_types[t_id]
                        found = False
                        for d in dups:
                            if d in self.internal_types:
                                containing_types |= self.internal_types[d]
                                found = True
                                # let's assume that the first dup in internal_types is
                                # sufficient
                                break
                        if found == False:
                            logging.error(
                                f"{t_id} not found in internal types")
                            shutil.move(self.logname, f"{self.out_dir}/{Generator.LOGFILE}")

                            sys.exit(1)
                    else:
                        containing_types |= self.internal_types[t_id]
                    # make sure that the containing type is not an internal type of yet another type ...
                    tmp = containing_types
                    found = True
                    while found:
                        found = False
                        next = set()
                        for _t_id in tmp:
                            if _t_id in self.internal_types:
                                next |= self.internal_types[_t_id]
                                found = True
                        if found:
                            containing_types |= next
                            tmp = next

            if len(containing_types) > 0:
                internal_defs = set()
                logging.info(f"we have found {len(containing_types)}")
                tmp, _ = self._get_types_recursive(
                    containing_types, [], internal_defs)
                tmp = self._remove_duplicated_types(tmp)
                global_types, global_fwd_str, global_defs_str, globals_ids = self._get_global_types(
                    functions, globs, tmp, True, internal_defs, file_id, global_type_decls)
                types = self._get_types_in_funcs(functions, internal_defs)
                logging.debug("File {} contains {} functions and {} types".format(
                    name, len(functions), len(types)))
                global_types = tmp + global_types

        else:
            # generating stubs file - we only care about types from the declaration
            types = self._get_types_in_funcs(
                functions, internal_defs, types_only=True)
            logging.debug("File {} contains {} functions and {} types".format(
                name, len(functions), len(types)))

        # remove duplicated types already coming from global types
        types_tmp = self._remove_duplicated_types(types)
        types = self._remove_duplicated_types_from(
            global_types, types_tmp)

        # generate code: types first, then functions
        failed_count = 0

        str = self._get_file_header()
        str_header = self._get_file_header()

        for h in self.include_std_headers:
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

        #str += Generator.AOT_INCLUDE_MARKER + "\n"
        str += f"#include \"{Generator.AOT_HEADER}\"\n"

        # check if we need to add the replacements include
        for f in functions:
            func = self.fnidmap[f]
            if func is not None:
                if "__replacement" in func["body"]:
                    str += "#include \"aot_replacements.h\"\n"

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
            functions_data = self.fnidmap.get_many(list(functions))
            if functions_data is not None:
                for func in functions_data:
                    if func["id"] not in self.internal_funcs:
                        # since a function is not an internal function we
                        # don't need to further discover its refs
                        continue
                    if func["id"] in self.known_funcs_ids:
                        continue
                    if not self.include_asm and func["id"] in self.all_funcs_with_asm:
                        continue
                    funref_ids = func["funrefs"]
                    for call_id in funref_ids:
                        # we're only interested in functions as they are defined
                        # elsewhere
                        if call_id in self.fnidmap:
                            if call_id not in functions:
                                additional_decls.add(call_id)
                        elif call_id in self.fdmap:
                            if call_id not in functions:
                                additional_decls_fdecls.add(call_id)
                del functions_data

            # same applies to globals which are defined inside this file
            # this is because global initializers can contain function references
            globals_data = self.globalsidmap.get_many(list(globs))
            if globals_data is not None:
                for g in globals_data:
                    funref_ids = g["funrefs"]
                    for call_id in funref_ids:
                        # we're only interested in functions as they are defined
                        # elsewhere
                        if call_id in self.fnidmap:
                            if call_id not in functions:
                                additional_decls.add(call_id)
                        elif call_id in self.fdmap:
                            if call_id not in functions:
                                additional_decls_fdecls.add(call_id)
                del globals_data

            add_types = set()

            additional_decls_data = self.fnidmap.get_many(
                list(additional_decls))
            additional_decls_fdecls_data = self.fdmap.get_many(
                list(additional_decls_fdecls))

            #
            for func in additional_decls_data:
                for t in func["types"]:
                    type = self.typemap[t]
                    if type["class"] == "pointer":
                        dst_type = self.typemap[type["refs"][0]]
                        dst_class = dst_type["class"]
                        if dst_class == "record" or dst_class == "enum" or dst_class == "builtin":
                            continue
                    if t not in types:
                        add_types.add(t)
            for func in additional_decls_fdecls_data:
                for t in func["types"]:
                    type = self.typemap[t]
                    if type["class"] == "pointer":
                        dst_type = self.typemap[type["refs"][0]]
                        dst_class = dst_type["class"]
                        if dst_class == "record" or dst_class == "enum" or dst_class == "builtin":
                            continue
                    if t not in types:
                        add_types.add(t)

            if len(add_types) != 0:
                # we have some additional types to define; now we need to get their
                # dependencies
                add_types_rec, _ = self._get_types_recursive(
                    add_types, list(types) + list(global_types), internal_defs)

                add_types_rec = self._remove_duplicated_types(
                    add_types_rec)
                add_types = self._remove_duplicated_types_from(
                    list(types) + list(global_types), add_types_rec)

            else:
                add_types = []
            del additional_decls_data
            del additional_decls_fdecls_data

            # let's unify all the types
            types += add_types
            types += global_types
            types, _ = self._get_types_recursive(types, None, internal_defs)
            types = self._remove_duplicated_types(types)

            # once we have all the types, we need to make sure that
            # some of them are not defined by others (in which case it makes sense
            # to generate the code only for the declaring outer type)
            # "internal_defs" set should store all the types defined inside other types
            self._filter_internal_types(types, internal_defs)

            if self.dynamic_init:
                str_header += "\n/* Dynamic init decls */\n"
                str_header += "#include \"dyn_init.h\"\n"

            str_header += "\n/* Type decls */\n"
            tmp = []
            tmp += types
            tmp += list(global_type_decls)
            if create_header:
                str_header += self._get_type_decls(tmp)

            globs_in_types = {}

            for t_id in types:  # global_types:
                t = self.typemap[t_id]
                if "globalrefs" in t:
                    globs_in_types[t_id] = set(t["globalrefs"])
                    globals_ids |= globs_in_types[t_id]

                decls = set()
                refs = set()
                self._discover_type_decls_and_refs(t, decls, refs)
                # check if any of the internally defined types might have global references
                for subt_id in decls:
                    t = self.typemap[subt_id]
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
                funcs_in_types = self._get_funcs_from_types([t_id])

                # remove the functions we already inserted
                for f_id in inserted_funcs:
                    if f_id in funcs_in_types:
                        funcs_in_types.remove(f_id)

                if len(funcs_in_types) != 0:
                    logging.info(f"for type {self._get_typename_from_type(self.typemap[t_id])} we found {len(funcs_in_types)} related functions")

                    f_types = self._get_types_in_funcs(funcs_in_types, internal_defs, types_only=True)
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
                    #for _t_id in _types:
                    #    logging.info(f"type {self._get_typename_from_type(self.typemap[_t_id])}")
                    #sys.exit(1)
                index += 1

            types_str, failed = self._get_type_defs(types, funcs_for_type, fid, static_funcs)
            str_header += "\n/* Global type defs */\n"
            for t_id in types_str:

                if t_id in globs_in_types:
                    # this means that this specific global type referneces other globals
                    # we need to put these other globals fwd decl before that type
                    for gt_id in globs_in_types[t_id]:
                        str_header += "// fwd decl of a global used in the global type below\n"
                        if gt_id in global_fwd_str:
                            if create_header:
                                _str_header, ifgenerated = self._get_type_clash_ifdef(
                                    gt_id, fid)
                                str_header += _str_header
                                str_header += f"{global_fwd_str[gt_id]}\n"
                                str_header += self._get_type_clash_endif(
                                    gt_id, fid, ifgenerated)
                            del global_fwd_str[gt_id]
                        else:
                            g = self.globalsidmap[gt_id]
                            def_str = g["def"]
                            if create_header:
                                _str_header, ifgenerated = self._get_type_clash_ifdef(
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
                                str_header += self._get_type_clash_endif(
                                    gt_id, fid, ifgenerated)
                _str_header, ifgenerated = self._get_type_clash_ifdef(t_id, fid) 
                str_header += _str_header
                str_header += types_str[t_id]
                str_header += self._get_type_clash_endif(t_id, fid, ifgenerated)
            failed_count += failed

        globals_defs = "\n\n// Global vars definitions\n\n"

        # globals forward
        str_header += "\n/* Forward decls of global vars */\n"
        for g_id in global_fwd_str:
            g = self.globalsidmap[g_id]
            if "decls" in g:
                skip = False

                decl_tids, real_tid = self._get_global_decl_types(
                    g["decls"], g["refs"], g["type"])

                if real_tid in decl_tids:
                    skip = True
                    if g_id in global_defs_str:  # that's true only if global is defined in this file
                        globals_defs += f"{global_defs_str[g_id]}\n"
                        del global_defs_str[g_id]

                if skip:
                    continue
            if create_header and g_id in global_fwd_str:
                str_header += self._get_global_clash_ifdef(g_id, fid)

                if fid == Generator.AOT_HEADER_ID and g["linkage"] != "internal":
                    prefix = "extern "
                    self.global_trigger_name_list_exclude.add("%s"%(g["hash"].replace("/","__").replace(".","____").replace("-","___")))
                else:
                    prefix = ""
                str_header += "{}{}\n".format(prefix, global_fwd_str[g_id])
                str_header += self._get_global_clash_endif(g_id, fid)

        # print function declarations
        if create_header:
            str_header += "\n\n#include \"aot_lib.h\"\n\n"
            str_header += "\n\n/* ----------------------------- */\n" +\
                "/* Function declarations section */\n" +\
                "/* ----------------------------- */\n\n"

            str_header += "\n/*Functions defined in this file*/\n"

            # do not declare functions which were declared along the types
            functions_copy = [f_id for f_id in functions if f_id not in inserted_funcs]
            additional_decls_copy = [f_id for f_id in additional_decls if f_id not in inserted_funcs]
            additional_decls_fdecls_copy = [f_id for f_id in additional_decls_fdecls if f_id not in inserted_funcs]

            str_header += self._get_func_decls(fid, functions_copy, static_funcs)
            str_header += "\n/* Additional function decls */\n"
            str_header += self._get_func_decls(fid,
                                                additional_decls_copy, section_header=False)
            str_header += self._get_func_decls(fid,
                                                additional_decls_fdecls_copy, section_header=False)

        if test_driver is False:
            # print globals
            str += "\n\n/* ----------------------------- */\n" +\
                "/* Globals definition section    */\n" +\
                "/* ----------------------------- */\n\n"
            # const globals go first as they might be used in the initializers
            ids = list(global_defs_str.keys())
            for g_id in ids:
                g = self.globalsidmap[g_id]
                if g["def"].startswith("const ") or g["def"].startswith("static const "):
                    globals_defs += f"{global_defs_str[g_id]}\n"
                    self.global_trigger_name_list.add("%s"%(g["hash"].replace("/","__").replace(".","____").replace("-","___")))
                    del global_defs_str[g_id]

            for g_id in global_defs_str:
                g = self.globalsidmap[g_id]
                globals_defs += f"{global_defs_str[g_id]}\n"
                self.global_trigger_name_list.add("%s"%(g["hash"].replace("/","__").replace(".","____").replace("-","___")))

            str += globals_defs

        if stubs == False:
            str_header += "\n/*Static inline headers*/\n"
            functions_copy = functions.copy()
            for f_id in functions_copy:
                if f_id in self.static_inline_headers:
                    if create_header and f_id not in self.known_funcs_ids:                        
                        str_header += self._get_func_defs(fid,
                                                          [f_id], section_header=False)
                    functions.remove(f_id)

        if test_driver is False:

            # print function definitions
            str += "\n\n/* ----------------------------- */\n" +\
                "/* Function definitions section  */\n" +\
                "/* ----------------------------- */\n"
            str += self._get_func_defs(fid, functions, stubs=stubs, file=name)

            # generate static functions wrappers
            if len(static_funcs) != 0:
                str += "\n\n/* ----------------------------- */\n" +\
                    "/* Static function wrappers      */\n" +\
                    "/* ----------------------------- */\n"
                for f in static_funcs:
                    function = self.fnidmap[f]
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
                    for l in function["locals"]:
                        if l["parm"] == True:
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
            str += f"\n{Generator.AOT_STATIC_GLOBS_FPTRS}\n"
            str += f"void aot_init_globals_file_{fid}(void) {{\n"
            str += f"\tchar* tmpname;\n"
            str += f"\n{Generator.AOT_STATIC_GLOBS_MARKER}\n"
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

    # -------------------------------------------------------------------------

    def _remove_duplicated_types(self, types, all=False):
        to_remove = []
        for t in types:
            if t in to_remove:
                continue
            if t in self.dup_types:
                dups = self.dup_types[t]
                for d in dups:
                    if d == t:
                        continue
                    if d in types:
                        to_remove.append(d)
                if all == True:
                    to_remove.append(t)
        for t in to_remove:
            types.remove(t)

        return types

    # given the _base array, remove all the duplicate types (considering all the variants)
    # from the _from array
    def _remove_duplicated_types_from(self, _base, _from):
        for t in _base:
            if t in _from:
                _from.remove(t)

            if t in self.dup_types:
                dups = self.dup_types[t]
                # we need to check if any of the duplicates is present
                # in the _base array
                present = False
                for d in dups:
                    if d in _base:
                        present = True
                        break
                if present:
                    for d in dups:
                        if d in _from:
                            _from.remove(d)
        return _from

    # -------------------------------------------------------------------------

    def _adjust_varlen_decl(self, g_tid, decl):
        # handle a special case when global is a var-length array
        # in these cases we need to concretize the length for the declaration
        # this is needed in order to prevent type incompleteness errors when the
        # global would be used before it's defined (and remember that we don't do toposort)
        g_type = self.typemap[g_tid]
        if g_type["class"] == "const_array":
            size_total = int(g_type["size"])

            # let's find the size of the array type
            # be careful: if the immediate type is typedef, we will need to
            # find a concrete type as typedefs' size is 0
            # refs should have just one element: type of the member
            items_tid = g_type["refs"][0]
            items_type = self.typemap[items_tid]
            items_type = self._get_typedef_dst(items_type)
            size_item = int(items_type["size"])
            if size_item != 0:
                items_count = size_total // size_item
                decl = decl.replace("[]", f"[{items_count}]")
        return decl

    # -------------------------------------------------------------------------

    # Removes 'const' qualifier from the variable definition
    def _vardecl_remove_const_qualifier(self,def_str):
        i = def_str.find("=")
        if i>0:
            def_str_proper = def_str[:i]
            def_str_init = def_str[i:]
        else:
            def_str_proper = def_str
            def_str_init = ""
        if "const " in def_str_proper:
            def_str_proper = def_str_proper.replace("const ","")
            def_str = def_str_proper+def_str_init
        return def_str

    # @types: the types we aleady know about
    def _get_global_types(self, functions, globs, types, section_header=True, internal_defs=None, file=None, type_decls=None):
        _str = ""

        # if section_header:
        #    _str += "\n\n/* ----------------------------- */\n" +\
        #            "/* Global variables section      */\n" +\
        #            "/* ----------------------------- */\n"

        logging.debug(
            "Getting global types, types len is {}".format(len(types)))
        # we need to do the following:
        # 1) discover which types are required by globals
        # 2) add decls/defs of those types (if we haven't already)
        # 3) define globals by using the original names and types

        # but first, let's get the globals
        globals_ids = set()
        globals_ids |= set(globs)  # include the known globals from "globs"
        for f in functions:
            if f in self.external_funcs:
                # for static inline functions we will have external stubs in a non-stub file
                # but since the functions are external we do not want to get the globals
                continue
            func = self.fnidmap[f]
            if func is not None:
                globals_ids |= set(func["globalrefs"])

        # we need to know if a global is defined in this file or somewhere else
        # this is important because for the globals outside of compilation unit
        # we need to provide extern keyword and for the internal ones we need to
        # emit the definition code

        globalTypes = set()
        # across globals there might be implicit dependencies
        # which arise when one global references other by name;
        # in order to handle that we emit forward declarations of global vars
        # NOTE: toposort of globals is a worse alternative, since circular dependencies
        # may arise
        global_defs_str = ""  # "\n\n// Forward declaration of global vars\n\n"
        global_defs_strings = {}
        globals_from_inits = set()
        globals_refs = set()
        global_fwd_str = {}
        global_type_decls = set()
        for g_id in globals_ids:
            g = self.globalsidmap[g_id]
            g_tid = g["type"]
            g_fid = g["fid"]
            # make sure that the type is not already there
            if g_tid not in types:
                globalTypes.add(g_tid)

            if "decls" in g:
                decl_tids, read_tid = self._get_global_decl_types(
                    g["decls"], g["refs"], g_tid)
                global_type_decls |= decl_tids
                internal_defs |= decl_tids

            local = True
            if (file is not None) and (g_fid != file):
                local = False

            def_str = g["def"]
            if self.dynamic_init:
                # Remove the 'const' qualifier from global variables when dynamic initialization is used
                def_str = self._vardecl_remove_const_qualifier(def_str)
            index = def_str.find("=")

            # special case double-check for register variables
            if def_str.startswith("register"):
                local = True

            if local:
                globals_refs |= set(g["refs"])

            global_fwd_str[g_id] = ""

            if local == False:
                if not def_str.startswith("extern"):
                    if not g["linkage"] == "internal":
                        global_defs_str += "extern "
                        logging.debug("Global {} is extern fid is {} gfid is {}".format(
                            g["name"], file, g_fid))
                    else:
                        # a special case: a static global is pulled in but should be external
                        # this can happen in the aot.h file
                        # we can't have both extern and static, so we comment it out
                        global_defs_str += "//below static global pulled in as a dependency and left as a reference\n"
                        global_defs_str += "//extern "
            if -1 != index:
                global_defs_str += "{};\n".format(def_str[:index])
            else:
                global_defs_str += "{};\n".format(def_str)

            if local:
                if self.dynamic_init:
                    def_string = "\n{};\n".format(g["def"].replace("extern ", "").replace("const ", "").split("=")[0].rstrip())
                    g_trigger_name = "%s"%(g["hash"].replace("/","__").replace(".","____").replace("-","___"))
                    g_type = self.typemap[g["type"]]
                    g_address_specifier = '&' if g_type["class"]!="const_array" and g_type["class"]!="incomplete_array" else ''
                    def_string += "\n{};\n".format(Generator.DYNAMIC_INIT_GLOBAL_VARIABLE_TEMPLATE.format(g["hash"], g_address_specifier, g["name"], g_trigger_name))
                else:
                    def_string = "\n{};\n".format(g["def"].replace("extern ", ""))
                global_defs_strings[g_id] = def_string
                globals_from_inits |= set(g["globalrefs"])

            global_defs_str = self._adjust_varlen_decl(g_tid, global_defs_str)

            global_fwd_str[g_id] += global_defs_str
            global_defs_str = ""

            # handle the special case of register + asm
            # it is a GCC extension to put variables in specific registers and looks like that
            # register unsigned long stack_pointer asm("sp");
            # since it's global we can't have it as a register variable in clang
            # also, asm is not portable
            # it seems that it shouldn't change semantics too much if we just
            # turn such variables into non-register ones
            # TODO: once asm inlines are added to db.json we can improve the detection
            # bit below
            if local and global_defs_strings[g_id].startswith("\nregister ") and "asm(\"" in global_defs_strings[g_id]:
                global_defs_strings[g_id] = global_defs_strings[g_id].replace(
                    "\nregister ", "\n ")
                index = global_defs_strings[g_id].find("asm(\"")
                global_defs_strings[g_id] = f"{global_defs_strings[g_id][:index]};\n"
            if global_fwd_str[g_id].startswith("register ") and "asm(\"" in global_fwd_str[g_id]:
                global_fwd_str[g_id] = global_fwd_str[g_id].replace(
                    "register ", "")
                index = global_fwd_str[g_id].find("asm(\"")
                global_fwd_str[g_id] = f"{global_fwd_str[g_id][:index]};\n"

        globals_from_inits = globals_from_inits.difference(globals_ids)
        for g_id in globals_from_inits:
            g = self.globalsidmap[g_id]
            g_tid = g["type"]
            g_fid = g["fid"]
            # make sure that the type is not already there
            if g_tid not in types:
                globalTypes.add(g_tid)

            if "decls" in g:
                decl_tids, read_tid = self._get_global_decl_types(
                    g["decls"], g["refs"], g_tid)
                global_type_decls |= decl_tids
                internal_defs |= decl_tids

            def_str = g["def"]
            index = def_str.find("=")

            global_fwd_str[g_id] = ""
            if (file is not None) and (g_fid != file) and not def_str.startswith("extern"):
                if not g["linkage"] == "internal":
                    global_defs_str += "extern "
                else:
                    # a special case - like above
                    global_defs_str += "//below static global pulled in as a dependency and left as a reference\n"
                    global_defs_str += "//extern "
            if -1 != index:
                global_defs_str += "{};\n".format(def_str[:index])
            else:
                global_defs_str += "{};\n".format(def_str)

            global_defs_str = self._adjust_varlen_decl(g_tid, global_defs_str)

            global_fwd_str[g_id] += global_defs_str
            global_defs_str = ""

        # globals can reference other types, eg. enums in their initializers
        globalTypes |= globals_refs

        if type_decls != None and internal_defs != None:
            type_decls |= internal_defs

        if len(globalTypes) != 0:
            globalTypes, _ = self._get_types_recursive(
                globalTypes, types, internal_defs)

            # we can have a duplicate across types and globalTypes, so we need to
            # filter that out (same type different ids)
            globalTypes = self._remove_duplicated_types(globalTypes)
            globalTypes = self._remove_duplicated_types_from(
                types, globalTypes)

        globalTypes = [
            g_id for g_id in globalTypes if g_id not in global_type_decls]
        for g_id in global_type_decls:
            if g_id in global_fwd_str:
                del global_fwd_str[g_id]

        # update the list of ids
        globals_ids |= globals_from_inits

        return globalTypes, global_fwd_str, global_defs_strings, globals_ids

    # -------------------------------------------------------------------------

    def _get_type_decls(self, types):
        str = ""
        types_data = self.typemap.get_many(list(types))

        for t in types_data:
            if t["class"] == "record" or t["class"] == "record_forward":
                if 0 != len(t["str"]):
                    if not t["union"]:
                        str += "struct "
                    else:
                        str += "union "
                    str += t["str"] + ";\n"
            elif t["class"] == "enum" or t["class"] == "enum_forward":
                if 0 != len(t["str"]):
                    str += "enum " + t["str"] + ";\n"
        del types_data
        return str

    # -------------------------------------------------------------------------

    def _get_type_defs(self, types, funcs_in_types=None, fid=None, static_funcs=None):
        str = {}
        failed_count = 0

        type_classes = set(["class", "enum", "enum_forward",
                            "record", "record_forward", "typedef"])

        multi_typedefs = set()
        types_data = self.typemap.get_many(list(types))
        for t in types_data:
            typedef_special = False
            add_names = ""
            tid = t["id"]

            if t["class"] not in type_classes:
                continue

            if t["class"] == "record" and self.verify_struct_layout:
                self.struct_types.append(t)

            if t["class"] == "typedef" and self.verify_struct_layout:
                resolved_type = self._get_typedef_dst(t)
                if resolved_type["class"] == "record":
                    self.struct_types.append(t)

            if t["class"] == "typedef" and "decls" in t and len(t["decls"]) != 0:
                # assuming a typedef has exactly one ref
                dst_tid = t["refs"][0]

                if dst_tid in self.identical_typedefs and len(self.identical_typedefs) > 1:
                    if dst_tid not in multi_typedefs:
                        multi_typedefs.add(dst_tid)
                        typedef_special = True
                        for id in self.identical_typedefs[dst_tid]:
                            if id == tid:
                                continue
                            if id in types:
                                add_names += f", {self.typemap[id]['name']}"
                    else:
                        continue

            if "def" not in t:
                logging.error("def not in {}".format(t))
            if self.used_types_only and "useddef" in t:
                def_str = f"{t['defhead']} {{\n"
                for d_str in t['useddef']:
                    def_str += f"\t{d_str}\n"
                def_str += "}"
            else:
                def_str = t["def"]

            str[tid] = ""
            if funcs_in_types is not None and fid is not None and static_funcs is not None:
                if tid in funcs_in_types:            
                    str[tid] += "/* Func decls necessary for the type */\n"
                    # prepend the type def with necessary func decls
                    str[tid] += self._get_func_decls(fid, funcs_in_types[tid], [], section_header=False)            

            
            if len(def_str) != 0:
                str[tid] += "{}".format(def_str)
                if typedef_special:
                    str[tid] += f"{add_names}"
                str[tid] += ";\n"
            else:
                logging.error(
                    "Failed to generate type {}: definition string is empty".format(tid))
                failed_count += 1
        del types_data
        return str, failed_count

    # -------------------------------------------------------------------------

    def _get_func_decls(self, fid, functions, static_functions=[], section_header=True):
        str = ""
        # if section_header:
        #    str += "\n\n/* ----------------------------- */\n" +\
        #        "/* Function declarations section */\n" +\
        #        "/* ----------------------------- */\n"
        funcs = [f for f in functions if self.fnidmap[f] is not None]
        # a function cannot be func and funcdelc at the same time
        remaining = [f for f in functions if f not in funcs]
        funcdecls = [f for f in remaining if self.fdmap[f] is not None]

        # there is one special case in funcs: inline functions with external linkage
        # those should be declared as non-inline in multiple places and keep inline
        # definition in their corresponding source file
        for f in funcs:
            if f not in static_functions:
                func = self.fnidmap[f]
                decl = func["declbody"]
                if f in self.lib_funcs_ids:
                    decl = decl.replace("static ", "extern ")
                if "inline" in func and func["inline"] and func["linkage"] == "external":
                    if decl.startswith("inline "):
                        decl = decl.replace("inline ", "")
                decl = self._filter_out_asm_in_fdecl(decl)
                decl = decl.replace(
                    '__attribute__((warn_unused_result("")))', "")
                str += self._get_func_clash_ifdef(f, fid)
                str += f"\n\n{decl};\n"
                str += self._get_func_clash_endif(f, fid)

        str += "\n// Func decls\n"
        for f in funcdecls:
            if f not in static_functions:
                func = self.fdmap[f]
                decl = func["decl"]
                if f in self.lib_funcs_ids:
                    decl = decl.replace("static ", "extern ")
                decl = self._filter_out_asm_in_fdecl(decl)
                decl = decl.replace(
                    '__attribute__((warn_unused_result("")))', "")
                str += self._get_func_clash_ifdef(f, fid)
                str += f"\n\n{decl};\n"
                str += self._get_func_clash_ifdef(f, fid)

        for f_id in static_functions:
            if f_id in self.static_inline_headers:
                # for static inline functions we don't generate wrappers
                # as the entire function's body is located in the header file
                # note: the keys of the static_inline_headers dict are in fact the
                # ids of static inline functions
                continue
            f = self.fnidmap[f_id]
            name = f["name"]
            str += self._get_func_clash_ifdef(f_id, fid)
            str += "\n\n"
            body = f["declbody"].replace(
                "{}(".format(name), "wrapper_{}_{}(".format(name, f_id))
            body = body.replace("static ", "")
            body = body.replace("inline ", "")
            body = self._filter_out_asm_in_fdecl(body)
            body = body.replace('__attribute__((warn_unused_result("")))', "")
            str += "{};\n".format(body)
            body = f["declbody"]
            body = self._filter_out_asm_in_fdecl(body)
            body = body.replace('__attribute__((warn_unused_result("")))', "")
            str += "{};\n".format(body)
            str += self._get_func_clash_endif(f_id, fid)
        return str

    # -------------------------------------------------------------------------

    def _get_func_defs(self, fid, functions, section_header=True, stubs=False, file=""):
        str = ""
        # if section_header:
        #    str += "\n\n/* ----------------------------- */\n" +\
        #        "/* Function definitions section  */\n" +\
        #        "/* ----------------------------- */\n"
        if stubs is False:
            for f_id in functions:
                tmp = ""
                tmp += self._get_func_clash_ifdef(f_id, fid)
                if self.fnidmap[f_id] is not None:
                    if f_id not in self.external_funcs:
                        if not self.dbjson2:
                            tmp += self._filter_out_asm_inlines(
                                f_id, self.fnidmap[f_id]["body"], file)
                        else:
                            tmp += self._filter_out_asm_inlines(
                                f_id, self.fnidmap[f_id]["unpreprocessed_body"], file)
                        self.generated_functions += 1
                        if tmp.startswith("extern "):
                            # if we define a function we don't need to have the extern specifier
                            tmp = tmp.replace("extern ", "", 1)
                        if self.dynamic_init and ("inline" not in self.fnidmap[f_id] or self.fnidmap[f_id]["inline"] is not True):
                            tmp += "\n%s"%(self._get_function_pointer_stub(self.fnidmap[f_id]))
                    else:
                        # this is not a stubs file but we might have a stub of a static function inside
                        tmp += self._generate_function_stub(f_id, stubs_file=stubs)
                        if (len(tmp) > 0) and (f_id not in self.static_inline_headers):
                            tmp = self._get_func_decls(
                                fid, [], [f_id], section_header=False) + "\n" + tmp
                    if len(tmp) > 0:
                        tmp += self._get_func_clash_endif(f_id, fid)
                        tmp += "\n\n"
                    
                    str += tmp.replace('__attribute__((warn_unused_result("")))', "")                
        else:
            for f_id in functions:
                str += self._get_func_clash_ifdef(f_id, fid)
                str += self._generate_function_stub(f_id, stubs_file=stubs)
                str += self._get_func_clash_endif(f_id, fid)
                str += "\n\n"
        
        return str

    # -------------------------------------------------------------------------

    def _get_file_header(self):
        str = "/* ------------------------------------------------ */\n" +\
              "/* AOT generated this file                          */\n" +\
              "/* Copyright Samsung Electronics                    */\n" +\
              "/* ------------------------------------------------ */\n"

        return str

    # -------------------------------------------------------------------------

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

    # -------------------------------------------------------------------------

    # the purpose of this function is to discover all immediate dependencies and
    # type definitions within types
    # For example, let's assume we have:
    # struct A {
    #   struct {
    #       atomic_t a;
    #       struct {
    #           lock_t b;
    #       }
    #   }
    #   struct B b;
    # }
    # The immediate dependencies would be the types one can immediatelly spot:
    # atomic_t, lock_t and struct B. The type definitions would be two annonymous
    # structs defined inside struct A.
    # Why?: when we emit types we use "def" field in the db.json. That field contains
    # whole textual form of enum/struct. However, we need to generate types in the right
    # order to prevent compilation errors and for that we have to know dependecies and
    # which types are defined inside others
    def _discover_type_decls_and_refs(self, t, internal_defs, refs, checked_types=None):

        local_refs = set()
        usedrefs = False
        if self.used_types_only and "class" in t and t["class"] == "record":
            local_refs = set(t["usedrefs"])
            usedrefs = True
        else:
            local_refs = set(t["refs"])
        removed_types = set()

        if checked_types is not None:
            checked_types.add(t['id'])

        # consider type of global; this is an implicit reference, but if we use a name
        # of a global (e.g. in sizeof or typeof) we will need to pull in the associated
        # type
        if "globalrefs" in t:
            for g_id in t["globalrefs"]:
                glob = self.globalsidmap[g_id]
                g_tid = glob["type"]
                local_refs.add(g_tid)
                if "decls" in glob:
                    decl_tids, real_tid = self._get_global_decl_types(
                        glob["decls"], glob["refs"], g_tid)
                    internal_defs |= decl_tids
                    removed_types |= decl_tids

        if "decls" in t:
            logging.debug("discover")
            # we skip those types which are defined within other types
            # this is because their definition will already be printed out
            # as a part of "def";
            # if "decls" array is present in the type, it contains indices
            # of "refs" which are declarations rather than just uses of types
            decls = t["decls"]
            for i in decls:
                if usedrefs:
                    id = t["usedrefs"][i]
                    if -1 == id:
                        continue
                else:
                    id = t["refs"][i]
                if id not in local_refs:
                    # this can happen when id was already removed from refs
                    continue

                local_refs.remove(id)
                internal_defs.add(id)
                removed_types.add(id)
                # when we remove a type from refs we need to make sure
                # that we also check the refs of that removed type:
                # it can be that we are removing a union/struct that has a field
                # of type declared somewhere else
                # we need to add those refs of the removed type, which are not
                # defined inside of it

        refs |= local_refs
        rem_types = []
        if checked_types is not None:
            removed_types.difference_update(checked_types)
        if len(removed_types) != 0:
            rem_types = self.typemap.get_many(list(removed_types))
            if checked_types is None:
                checked_types = set()
        for rem_type in rem_types:
            self._discover_type_decls_and_refs(rem_type, internal_defs, refs, checked_types)

    # -------------------------------------------------------------------------

    # A generic function for recursive retrieval of data
    # @collection - collection name
    # @items - list o items to begin with
    # @match_from_field - name of the field to match
    # @skip_list - items to skip in the results
    def _get_recursive_by_id(self, collection, items, match_from_field, skip_list=None):
        all_items = set()

        for i in items:

            if self.globs_tree_globalrefs is not None and collection == "globals" and match_from_field == "globalrefs":
                result_ids = self._graph_dfs(self.globs_tree_globalrefs, i)  # = self.globs_tree_globalrefs[i][match_from_field]
            elif self.types_tree_refs is not None and collection == "types" and match_from_field == "refs":
                result_ids = self._graph_dfs(self.types_tree_refs, i)#= self.types_tree_refs[i][match_from_field]
            elif self.types_tree_usedrefs is not None and collection == "types" and match_from_field == "usedrefs":
                result_ids = self._graph_dfs(self.types_tree_usedrefs, i)#= self.types_tree_usedrefs[i][match_from_field]
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

    def _get_types_recursive(self, types, base_types=None, internal_defs=None):
        if self.used_types_only:
            all_types = self._get_recursive_by_id(
                "types", types, "usedrefs", base_types)
        else:
            all_types = self._get_recursive_by_id(
                "types", types, "refs", base_types)
        logging.debug("Getting type deps for {} types".format(len(all_types)))
        # since the order is not guaranteed,
        # we need to perform topological sort
        deps = {}
        _internal_defs = set()
        all_types_data = self.typemap.get_many(list(all_types))

        for t in all_types_data:
            tid = t["id"]

            if tid in self.deps_cache:
                deps[tid] = self.deps_cache[tid]["refs"]
                _internal_defs |= self.deps_cache[tid]["defs"]
                continue

            _internal_defs_single = set()

            cl = t["class"]
            if cl == "builtin":
                continue

            refs = set()
            self._discover_type_decls_and_refs(t, _internal_defs_single, refs)
            refs_types = self.typemap.get_many(list(refs))

            for r in refs_types:
                tmp = r  # self.typemap[r]
                if tmp["class"] == "pointer":
                    # logging.info("pointer")
                    # remove pointers to structs and enums from deps
                    dst = tmp["refs"]
                    if len(dst) != 1:
                        logging.warning(
                            "Expected exactly one ref for a pointer")
                        continue
                    dst_type = self.typemap[dst[0]]

                    if dst_type["class"] == "record" or dst_type["class"] == "enum":
                        # pointers to enums and structs cause circular dependencies
                        logging.debug("Removing dep {}".format(r["id"]))
                        refs.remove(r["id"])

            deps[tid] = refs

            # due to possible type dups, let's extend internal_defs with
            # all potential duplicates
            dups = set()
            for d in _internal_defs_single:
                if d in self.dup_types:
                    dups |= set(self.dup_types[d])
            _internal_defs_single |= dups
            # if tid not in self.deps_cache:
            # since getting type dependencies right takes a lot of time
            # we cache the deps locally (as ids)
            self.deps_cache[tid] = {}
            self.deps_cache[tid]["refs"] = deps[tid]
            self.deps_cache[tid]["defs"] = _internal_defs_single

            _internal_defs |= _internal_defs_single

        del all_types_data
        logging.debug("Toposort types")
        try:
            sorted = toposort_flatten(deps)
        except CircularDependencyError as e:
            logging.warn("Circular depdencies detected")

            # typedefs are known to cause circular deps problem
            # because it's hard to find a generic rule for cicles removal,
            # we decided to remove deps on toposort failure

            for tid, tid_deps in e.data.items():
                type = self.typemap[tid]
                if type["class"] == "typedef":
                    dst_tid = type["refs"][0]
                    dst_type = self.typemap[dst_tid]
                    dst_class = dst_type["class"]
                    if dst_class == "record" or dst_class == "enum":
                        dst_tid = dst_type["id"]
                        if dst_tid in tid_deps:
                            deps[tid].remove(dst_tid)
                            logging.info(
                                "Breaking dependency from {} to {}".format(tid, dst_tid))
            logging.info("Retry toposort after circle removal")
            sorted = toposort_flatten(deps)

        sorted_types = self.typemap.get_many(list(sorted))
        sorted = [t["id"] for t in sorted_types if t["class"] != "builtin"
                  and t["id"] not in _internal_defs]
        logging.debug("sorted is {}".format(sorted))
        del sorted_types

        # adding type deps might have added types that we don't want to have
        # those are defined in base_types and need to be filtered out
        if base_types is not None:
            sorted = [t for t in sorted if t not in base_types]

        if None != internal_defs:
            internal_defs |= _internal_defs

        return sorted, deps

    # -------------------------------------------------------------------------

    # @functions: all the functions present in the generated code
    def _get_types_in_funcs(self, functions, internal_defs, types_only=False):
        _internal_defs = set()

        ftypes = set()
        for f in functions:
            # types we're interested in are coming from
            # - all the variables used in the function's body
            # - function params and return type
            f_obj = self.fnidmap[f]

            if f_obj is not None:
                if types_only is False:
                    if f not in self.external_funcs:
                        # if a function is external we don't want to get all
                        # the types used in its body
                        for t in f_obj["refs"]:
                            ftypes.add(t)
                for t in f_obj["types"]:
                    ftypes.add(t)

                # handle types defined inside functions
                self._discover_type_decls_and_refs(
                    f_obj, _internal_defs, ftypes)
                for t in _internal_defs:
                    if t in ftypes:
                        ftypes.remove(t)
            else:
                # assume funcdecls
                f_obj = self.fdmap[f]
                if f_obj is None:
                    logging.error(
                        "Unable to find func or funcdecl for id {}".format(f))
                    continue
                    #sys.exit(1)
                for t in f_obj["types"]:
                    ftypes.add(t)

        logging.debug("Getting types in funcs")
        ftypes, _ = self._get_types_recursive(ftypes, None, _internal_defs)


        logging.debug("Removing dups")

        internal_defs |= _internal_defs
        return self._remove_duplicated_types(ftypes)

    # -------------------------------------------------------------------------

    # @addtional_refs: the user might specify additional references which will be
    # injected into the lookup; this is helpful when we have implicit dependencies with
    # global variables - a function uses a global var that has another function in it's
    # initializer; by injecting those additional references in a lookup we might perform a
    # single db query rather than N queries (for each such function)
    def _get_called_functions(self, functions, additional_refs=None, filter_on=True, discover_known=False, calls_only=False):
        fcalls = set()

        # please note that we use "funrefs" here
        # this is because "funrefs" is a superset of "calls" in db.json
        # the "funrefs" array contains all references to functions inside a function;
        # that can be: a call and use by name (e.g. in function pointers)
        for f in functions:
            if f in fcalls:
                # if the id is already in the results set, there is no need to
                # query as the query is always recursive
                continue
            else:
                if filter_on:
                    cutoff = set(self.known_funcs_ids)
                    logging.info(f"Will use {len(cutoff)} known ids")
                    if 0 == len(cutoff):
                        cutoff = None
                else:
                    cutoff = None

                if not self.include_asm:
                    if cutoff is None:
                        cutoff = set()
                    # if we don't want to include assembly, we can cut the serach short
                    # whenever a function with inline asm is encountered
                    cutoff |= self.all_funcs_with_asm

                logging.debug("fcalls size is {}".format(len(fcalls)))


            used_map = None

            if cutoff is None:
                if not calls_only:
                    used_map = self.funcs_tree_funrefs
                else:
                    used_map = self.funcs_tree_calls
            else:
                if filter_on and not self.include_asm:
                    if not calls_only:
                        used_map = self.funcs_tree_funrefs_no_known_no_asm
                    else:
                        used_map = self.funcs_tree_calls_no_known_no_asm
                elif filter_on and self.include_asm:
                    if not calls_only:                    
                        used_map = self.funcs_tree_funrefs_no_known
                    else:
                        used_map = self.funcs_tree_calls_no_known
                else:
                    if not calls_only:
                        used_map = self.funcs_tree_funrefs_no_asm
                    else:
                        used_map = self.funcs_tree_calls_no_asm

            if used_map is not None:
                if additional_refs is None:
                    result = []
                    #if f in used_map:
                        #result = used_map[f]["funrefs"]
                    result = self._graph_dfs(used_map, f)
                    if f not in result:
                        result.append(f) 
                else:
                    tmp = set()
                    for f_id in additional_refs:
                        tmp |= set(self._graph_dfs(used_map, f_id))
                        #if f_id in used_map:
                        #    tmp |= set(used_map[f_id]["funrefs"])
                        tmp.add(f_id)
                    #tmp |= set(used_map[f]["funrefs"])
                    tmp |= set(self._graph_dfs(used_map, f))
                    
                    tmp.add(f)

                    result = list(tmp)                
            else:
                if not calls_only:
                    field = "funrefs"
                else:
                    field = "calls"

                result = self.db.make_recursive_query(
                    "funcs",
                    "id",
                    f,
                    field,
                    "id",
                    value_to_return="id",
                    add_vals=additional_refs,
                    cutoff_list=cutoff)
            for r in result:
                fcalls.add(r)

        functions |= fcalls

        for f in functions:
            func = self.fnidmap[f]
            if None != func:
                # some of the funrefs might be funcdels rather then functions
                if not calls_only:
                    fcalls |= set(func["funrefs"])
                else:
                    fcalls |= set(func["calls"])

        functions |= fcalls

        if filter_on:
            logging.info(f"functions size before filtering {len(functions)}")
            # filter out knonw functions before returning results
            self._filter_out_known_functions(functions, discover_known)
            logging.info(f"functions size after filtering {len(functions)}")

        self._filter_out_builtin_functions(functions)

        return functions

    # -------------------------------------------------------------------------

    # return a random name
    def _get_random_name(self, prefix=""):
        name = ""
        while True:
            name = prefix
            name += "_"
            name += str(random.randint(0, sys.maxsize))
            if name in self.random_names:
                continue
            self.random_names.add(name)
            break

        return name

# ------------------------------------------------------------------------------


def main():
    start_time = datetime.now()
    FORMAT = "%(asctime)-15s [AOT]: %(message)s (@ %(funcName)s:%(lineno)d)"
    (fd, logname) = tempfile.mkstemp(dir=os.getcwd())
    logging.basicConfig(filename=logname, filemode="w",
                        level=logging.INFO, format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
    # https://stackoverflow.com/questions/13733552/logger-configuration-to-log-to-file-and-print-to-stdout
    format = logging.Formatter(FORMAT)
    streamlog = logging.StreamHandler(sys.stdout)
    streamlog.setFormatter(format)
    logging.getLogger().addHandler(streamlog)

    logging.info("We are happily running with the following parameters:")
    argvcopy = sys.argv[:]
    argvcopy[0] = os.path.abspath(argvcopy[0])
    logging.info("AOT_RUN_ARGS: |" + " ".join(argvcopy[:]) + "|")

    db_frontend = aotdb.connection_factory(aotdb.DbType.FTDB) 

    parser = argparse.ArgumentParser(
        description='Auto off-target generator: "Select a function, generate a program, test a subsystem®"', conflict_handler="resolve")
    
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
    parser.add_argument('--output-dir', default=Generator.DEFAULT_OUTPUT_DIR,
                        help="A path to the output directory (default: {})".format(Generator.DEFAULT_OUTPUT_DIR))
    co_help = 'select cut-off algorithm: ' +\
              '{} - do not cut off anything, ' +\
              '{} - cut off everything outside off-traget function\'s module, ' +\
              '{} - cut off everything outside of the functions list (see the --co-funcs param), ' +\
              '{} - cut off everything outside of the specified directories (see the --co-dirs param), ' +\
              '{} - cut off everything outside of the specified files (see the --co-files param), ' +\
              '{} - cut off everythong outside of the specified modules (see the -co-modules param)'
    co_help = co_help.format(
        Generator.CUT_OFF_NONE, Generator.CUT_OFF_FUNCTIONS, Generator.CUT_OFF_MODULE,
        Generator.CUT_OFF_DIRS, Generator.CUT_OFF_FILES, Generator.CUT_OFF_NAMED_MODULES)
    parser.add_argument('--cut-off', choices=[Generator.CUT_OFF_NONE, Generator.CUT_OFF_FUNCTIONS, Generator.CUT_OFF_MODULE,
                                              Generator.CUT_OFF_DIRS, Generator.CUT_OFF_FILES, Generator.CUT_OFF_NAMED_MODULES],
                        default=Generator.CUT_OFF_MODULE,
                        help=co_help)
    parser.add_argument('--co-funcs', nargs="+", default="",
                        help='a list of functions for use with the --cut-off option')
    parser.add_argument('--co-dirs', nargs="+", default="",
                        help='a list of directories for use with the --cut-off option')
    parser.add_argument('--co-modules', nargs="+", default="",
                        help='a list of modules for use with the --cut-off option')
    parser.add_argument('--co-files', nargs="+", default="",
                        help='a list of files for use with the --cut-off option')

    parser.add_argument('--func-stats', choices=[Generator.FUNC_STATS_NONE, Generator.FUNC_STATS_BASIC, Generator.FUNC_STATS_DETAILED],
                        default=Generator.FUNC_STATS_BASIC,
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
    parser.add_argument("--kflat-img", default=Generator.KFLAT_IMAGE_NAME,
                        help="The name of the KFLAT image file.")
    parser.add_argument("--used-types-only", action='store_true',
                        help="When used, only the used types will be generated - this affects stucts and enums")
    parser.add_argument("--dbjson2", action='store_true',
                        help="When used, we know that we operate on a second db.json created from off-target")
    parser.add_argument("--rdm-file", default=None,
                        help='BAS-generated JSON file with location->module map')
    parser.add_argument("--init-file", default=None,
                        help='JSON file with init data')
    parser.add_argument("--source-root", default=None,
                        help='Specify base source directory for relative file paths (that start with a .)')
    parser.add_argument("--verify-struct-layout", action='store_true',
                        help=f"Add code to verify struct layout for generated struct types")
    parser.add_argument("--dump-global-hashes", action='store_true',
                        help=f"Dump hashes of globals to file {Generator.GLOBAL_HASH_FILE}")
    parser.add_argument("--debug-derefs", action='store_true',
                        help=f"Log debug messages from derefs parsing.")
    parser.add_argument("--stubs-for-klee", action="store_true",
                        help="When generating code for stubs returning pointers, add a special tag for KLEE")
    parser.add_argument("--always-inc-funcs-file", default=None,
                        help ='a path to a file which contains a list of functions that should always be included ' +
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
    parser.add_argument("--fptr-analysis", action="store_true",
                        help="When used, based on lightweight static analysis the code of possible functions that could be invoked through the function pointer calls are also added to the generated output")
    
    args = parser.parse_args()
    
    retcode = 0
    gen = Generator(logname)

    if False == gen.init(args, db_frontend):
        shutil.move(logname, f"{args.output_dir}/{Generator.LOGFILE}")
        sys.exit(1)

    logging.info(f"AOT_OUTPUT_DIR|{gen.out_dir}|")

    sys.setrecursionlimit(10000)

    funs = args.functions
    logging.info("Will generate off-target for functions {}".format(funs))
    gen.generate_off_target(args.functions, depth=10000)
    gen.deinit()
    # move the config to the output dir
    if args.config:
        shutil.copy(args.config, gen.out_dir)

    if args.db:
        abspath = os.path.abspath(args.db)
        dbname = os.path.basename(args.db)
        os.symlink(abspath, f"{gen.out_dir}/{dbname}" )
    args._get_args()
    end_time = datetime.now()
    logging.info(f"AOT_RUN_TIME_SECONDS: |{(end_time - start_time).total_seconds()}|")

    # move the log to the output dir
    shutil.move(logname, f"{args.output_dir}/{Generator.LOGFILE}")

    sys.exit(retcode)

if __name__ == "__main__":
    main()
