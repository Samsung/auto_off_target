#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

#
# Dependencies module
#


import logging
from toposort import toposort, toposort_flatten, CircularDependencyError
import struct
import re
import sys
import shutil


class Deps:

    INT_LITERAL = 'integer'
    FLOAT_LITERAL = 'floating'
    CHAR_LITERAL = 'character'
    STRING_LITERAL = 'string'
    AOT_LITERALS_FILE = 'aot_literals'
    MAX_STRING_LITERAL_LEN = 16

    # {0} - global variable trigger name
    # {1} - address specifier ('&' or '' in case of global variable array type)
    # {2} - global variable name
    # {3} - trigger name
    DYNAMIC_INIT_GLOBAL_VARIABLE_TEMPLATE = """void init_{3}() {{
    unsigned long target_size;
    void* ptr = aot_kflat_root_by_name("{0}", &target_size);
    if(ptr) {{
      memcpy({1}{2} ,ptr, target_size);
      aot_kflat_replace_variable(ptr, {1}{2}, target_size);
    }} else
      puts("[Unflatten] Failed to load global {0}");
}}"""

    def __init__(self, args):
        self.identical_typedefs = {}
        self.implicit_types = set()
        self.dup_types = {}
        self.internal_types = {}
        self.global_types = set()
        self.deps_cache = {}
        self.args = args
        # known functions are those that will be provided by the target system/env
        # e.g. printf
        self.known_funcs_present = set()

        self.clash_type_to_file = {}
        self.clash_global_to_file = {}
        self.clash_function_to_file = {}
        self.type_clash_nums = {}
        self.type_clash_counter = 0
        self.glob_clash_nums = {}
        self.glob_clash_counter = 0
        self.func_clash_nums = {}
        self.func_clash_counter = 0
        self.function_clashes = {}

        self.literals = {}
        self.literals[Deps.INT_LITERAL] = set()
        self.literals[Deps.FLOAT_LITERAL] = set()
        self.literals[Deps.CHAR_LITERAL] = set()
        self.literals[Deps.STRING_LITERAL] = set()

    def set_dbops(self, ops):
        self.dbops = ops

    def set_codegen(self, codegen):
        self.codegen = codegen

    def set_cutoff(self, cutoff):
        self.cutoff = cutoff

    # Analyzes function invocations through a pointer and tries to assign
    #  a list of possible functions that could be invoked through that pointer
    # Returns the following map:
    #  {
    #    function_id : [(expr,[called_fun_id,...]), ()...)]
    #  }
    # where,
    #  function_id: a function where the function invocation through a pointer takes place
    #  expr: the expression of the function invocation through a pointer
    #  called_fun_id: function id that could be possible stored (and invoked) through the pointer at the given expression
    def _infer_functions(self, json_data):

        # save all funcs
        funcsaddresstaken = set()
        funcsbytype = {}
        # first level struct assignment
        fucnsFirstLevelStruct = set()
        funccals = []

        for fun in json_data["funcs"]:
            for deref in fun["derefs"]:
                if deref["kind"] == "function":
                    funccals.append((deref, fun))

                if deref["kind"] != "assign" and deref["kind"] != "init":
                    continue
                functions = list(
                    filter(lambda x: x["kind"] == "function", deref["offsetrefs"]))
                if not functions:
                    continue
                for function in functions:
                    funcsaddresstaken.add(function["id"])

                # also handle first level struct assignment
                if deref["offsetrefs"][0]["kind"] != "member":
                    continue
                structDerefId = deref["offsetrefs"][0]["id"]
                structTypeId = fun["derefs"][structDerefId]["type"][-1]
                structMemberId = fun["derefs"][structDerefId]["member"][-1]

                for function in functions:
                    fucnsFirstLevelStruct.add(
                        (structTypeId, structMemberId, function["id"]))

            # also, consider the cases in which a function pointer is passed as a function parameter
            for i in range(len(fun["calls"])):
                info = fun["call_info"][i]
                for arg in info["args"]:
                    deref = fun["derefs"][arg]
                    if deref["kind"] == "parm":
                        functions = list(
                            filter(lambda x: x["kind"] == "function", deref["offsetrefs"]))
                        for function in functions:
                            funcsaddresstaken.add(function["id"])

        # from global variables take all funrefs as funcs with address taken
        for var in json_data["globals"]:
            for funid in var["funrefs"]:
                funcsaddresstaken.add(funid)

        funDict = {}
        for fun in json_data["funcs"]:
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

        globalDict = {}
        for glob in json_data["globals"]:
            globalDict[glob["id"]] = glob

        typeDict = {}
        for type in json_data["types"]:
            typeDict[type["id"]] = type

        fopbased = set()
        if "vars" in json_data["fops"]: # legacy format
            # seems that we need to add also those from fops
            recordsByName = {}
            for type in json_data["types"]:
                if type["class"] != "record":
                    continue
                recordsByName.setdefault(type["str"], [])
                recordsByName[type["str"]].append(type)
            
            for fop in json_data["fops"]["vars"]:
                for record in recordsByName[fop["type"]]:
                    for member in fop["members"]:
                        fucnsFirstLevelStruct.add(
                            (record["id"], int(member), fop["members"][member]))
                        fopbased.add(
                            (record["id"], member, fop["members"][member]))
        else:
            for fop in json_data["fops"]:
                record = typeDict.get(fop["type"])
                if record is not None:
                    for member in fop["members"]:
                        for f_id in fop["members"][member]:
                            fucnsFirstLevelStruct.add(
                                (record["id"], int(member), f_id))
                            fopbased.add(
                                (record["id"], member, f_id))

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
        for func in json_data["funcs"]:
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
                        # todo: not always the concrete type would be the first one
                        structType = typeDict[structType["refs"][0]]

                    if deref["member"][i] >= len(structType["refs"]):
                        continue

                    functype = typeDict[structType["refs"][deref["member"][i]]]
                    memberId = deref["member"][i]
                    while functype["class"] == "pointer" or functype["class"] == "typedef" or functype["class"] == "const_array":
                        functype = typeDict[functype["refs"][0]]
                    if functype["class"] == "function":
                        iCallsStruct.append(
                            ((structType["id"], memberId), deref, func, tuple(functype["refs"])))
                    elif functype["str"] == "void":
                        iCallsStruct.append(
                            ((structType["id"], memberId), deref, func, None))
                    else:
                        logging.error(f"Unsupported case found!")
                        logging.error(f">>> functype: {functype}")
                        logging.error(f">>> func: {func['name']}")
                        logging.error(f">>> deref: {deref}")
                        logging.error("Tracing function pointer calls")
                        continue

        output = {}
        for firstLevelId, deref, func, functypetuple in iCallsStruct:
            funcCandidates = []
            if firstLevelId in funcsbytypeFirstLevel:
                funcCandidates = [{"id": x["id"]}
                                  for x in funcsbytypeFirstLevel[firstLevelId]]
            elif functypetuple is not None and functypetuple in funcsbytype:
                funcCandidates = [{"id": x["id"]}
                                  for x in funcsbytype[functypetuple]]
            output.setdefault(func["id"], {})
            output[func["id"]][deref["expr"]] = funcCandidates

        iCallsVar = []
        for deref, fun in funccals:
            if deref["offsetrefs"][0]["kind"] == "unary":
                # deref = fun["derefs"][deref["offsetrefs"][0]["id"]]
                continue

            if deref["offsetrefs"][0]["kind"] == "global":
                typeId = globalDict[deref["offsetrefs"][0]["id"]]["type"]
            elif deref["offsetrefs"][0]["kind"] == "local":
                for l in fun["locals"]:
                    if l["id"] == deref["offsetrefs"][0]["id"]:
                        typeId = l["type"]
                        break
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
                funcCandidates = [{"id": x["id"]}
                                  for x in funcsbytype[functypetuple]]
                output.setdefault(func["id"], {})
                output[func["id"]][deref["expr"]] = funcCandidates

        return {
            func_id: [
                (expr, [x["id"] for x in v]) for expr, v in deref.items()
            ] for func_id, deref in output.items()
        }

    # -------------------------------------------------------------------------

    # @belongs: deps
    def _discover_known_functions(self, functions):
        for f_id in functions:
            if f_id in self.dbops.known_funcs_ids:
                self.known_funcs_present.add(
                    self.dbops._get_function_name(f_id))

    # -------------------------------------------------------------------------

    # Remove those functions that are known (e.g. memcpy)
    # @belongs: deps
    def _filter_out_known_functions(self, functions):
        functions.difference_update(set(self.dbops.known_funcs_ids))
        return functions

    # -------------------------------------------------------------------------

    # @belongs: deps
    def _filter_out_builtin_functions(self, functions):
        functions.difference_update(set(self.dbops.builtin_funcs_ids))
        return functions

    # -------------------------------------------------------------------------

    def _filter_out_replacement_functions(self, functions):
        functions.difference_update(set(self.dbops.replacement_funcs_ids))
        return functions

    # -------------------------------------------------------------------------

    # @belongs: deps
    def _filter_out_asm_functions(self, functions):
        if self.args.include_asm:
            return functions
        functions.difference_update(set(self.dbops.all_funcs_with_asm))
        return functions

     # -------------------------------------------------------------------------

    # Currently types in db.json which are used in const and non-const context appear
    # separately. This function is supposed to discover those duplicates and create
    # a local map for a quicker discovery
    # Since we iterate over all type objects we will use that to find implicit types.
    # Implicit types are those which are provided by a compiler.
    # @belongs: deps
    def discover_type_duplicates(self):
        logging.info("getting dups")
        hash_to_ids = {}
        for t in self.dbops.db["types"]:
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
    # @belongs: deps
    def discover_internal_types(self):

        for t in self.dbops.db["types"]:

            if "decls" in t and len(t["decls"]) > 0:
                for i in t["decls"]:
                    if self.args.used_types_only and t["class"] == "record":
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

    # from a list of types get all globals referenced in those types
    # @belongs: deps
    def _get_globals_from_types(self, types):
        globs = set()
        for t in self.dbops.typemap.get_many(types):
            if t is None:
                raise Exception("DB Error: Type is None") 
            if "globalrefs" in t:
                logging.debug(
                    "Adding globalrefs found in type {}".format(t["globalrefs"]))
                globs |= set(t["globalrefs"])

        return globs

    # -------------------------------------------------------------------------

    # from a list of globals get all globals referenced in those globals
    # @belongs: deps
    def _get_globals_from_globals(self, globals):
        globs = set()
        for g_id in globals:
            g = self.dbops.globalsidmap[g_id]
            if "globalrefs" in g:
                logging.debug(
                    "Adding globalrefs found in globals {}".format(g["globalrefs"]))
                globs |= set(g["globalrefs"])

        return globs

    # -------------------------------------------------------------------------

    # from a list of types get all functions referenced in those types
    # @belongs: deps
    def _get_funcs_from_types(self, types, skip_list=None):
        funcs = set()
        if skip_list:
            types_ids = [t_id for t_id in types if t_id not in skip_list]
        else:
            types_ids = types
        for t in self.dbops.typemap.get_many(types_ids):
            if "funrefs" in t:
                logging.debug(
                    "Adding funrefs found in types {}".format(t["funrefs"]))
                funcs |= set(t["funrefs"])

        return funcs

    # -------------------------------------------------------------------------

    # from a list of globals get all functions referenced in those globals
    # @belongs: deps
    def _get_funcs_from_globals(self, globals, skip_list=None):
        funcs = set()
        for g_id in globals:
            if skip_list is not None and g_id in skip_list:
                continue
            g = self.dbops.globalsidmap[g_id]
            if "funrefs" in g:
                logging.debug(
                    "Adding funrefs found in globals {}".format(g["funrefs"]))
                funcs |= set(g["funrefs"])
        return funcs

    # -------------------------------------------------------------------------

    # Get all functions and globals.
    # In C functions can reference other functions and globals and globals can reference other globals and functions.
    # On top of that types can reference functions and globals.
    # In this function we try to discover all the dependencies
    # @belongs: deps
    def _discover_functions_and_globals(self, functions, globals, all_types, basedirs, internal_defs=None):
        # get a recursive list of all functions called by our functions of choice
        # logging.info("Getting called functions for {} functions".format(len(functions)))
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
        globals_ids |= set(self.dbops._get_recursive_by_id(
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

        if len(self.cutoff.internal_funcs) > 0:
            tmp = g_funcs.difference(self.cutoff.internal_funcs)
            # we are only interested in internal functions
            g_funcs.intersection_update(self.cutoff.internal_funcs)
            # at the same time, we need to make sure that we update external funcs appropriately
            # that is to add everything that we've found but which was not in the internal functions
            # even though we will not generate the bodies of those functions, we would need to have them
            # beacause they are referenced by globals that we will generate
            self.cutoff.external_funcs |= tmp

        # let's check if new functions were discovered in globals
        if 0 != len(g_funcs):
            # we've found that globals reference other functions

            logging.info(
                "There are {} additional functions in the global initializers".format(len(g_funcs)))
            to_query = set()
            # we need _some_ function to begin the query; refs will be injected into its funrefs field
            for f in functions:
                if f in self.dbops.fnidmap:
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
            if len(self.cutoff.internal_funcs) > 0:
                to_query.intersection_update(self.cutoff.internal_funcs)

            to_query.difference_update(functions)

            if len(to_query) > 0:
                f, g = self._discover_functions_and_globals(
                    to_query, globals, all_types, basedirs, internal_defs)
                if len(self.cutoff.internal_funcs) > 0:
                    f.intersection_update(self.cutoff.internal_funcs)
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
    # @belongs: deps
    def _discover_type_decls_and_refs(self, t, internal_defs, refs, checked_types=None):

        local_refs = set()
        usedrefs = False
        if self.args.used_types_only and "class" in t and t["class"] == "record":
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
                glob = self.dbops.globalsidmap[g_id]
                g_tid = glob["type"]
                local_refs.add(g_tid)
                if "decls" in glob:
                    decl_tids, real_tid = self.dbops._get_global_decl_types(
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
            rem_types = self.dbops.typemap.get_many(list(removed_types))
            if checked_types is None:
                checked_types = set()
        for rem_type in rem_types:
            self._discover_type_decls_and_refs(
                rem_type, internal_defs, refs, checked_types)

    # -------------------------------------------------------------------------

    # @belongs: otgenerator or deps -> deps more likely
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
                continue

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
                # both functions are used in exactly the same files -> no need to create
                # header guards
                logging.debug(f"identical files for {f_id1} {f_id2}: {fid1_files}")
                continue

            if f_id1 not in self.clash_function_to_file:
                self.clash_function_to_file[f_id1] = set()
            self.clash_function_to_file[f_id1] |= fid2_files
            if f_id2 not in self.clash_function_to_file:
                self.clash_function_to_file[f_id2] = set()
            self.clash_function_to_file[f_id2] |= fid1_files

            if f_id1 not in self.function_clashes:
                self.function_clashes[f_id1] = set()
            if f_id2 not in self.function_clashes:
                self.function_clashes[f_id2] = set()
            self.function_clashes[f_id1].add(f_id2)
            self.function_clashes[f_id2].add(f_id1)

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
                if g_id in file.globals:
                    gid_files.add(g_id)

            if fid_files == gid_files:
                continue

            if f_id not in self.clash_function_to_file:
                self.clash_function_to_file[f_id] = set()
            self.clash_function_to_file[f_id] |= gid_files
            if g_id not in self.clash_global_to_file:
                self.clash_global_to_file[g_id] = set()
            self.clash_global_to_file[g_id] = fid_files

    # -------------------------------------------------------------------------

    # @belongs: codegen or deps
    def capture_literals(self, global_ids, function_ids):

        for g_id in global_ids:
            g = self.dbops.globalsidmap[g_id]
            if "literals" in g:
                literals = g["literals"]
                self.literals[Deps.INT_LITERAL] |= set(
                    literals[Deps.INT_LITERAL])
                self.literals[Deps.FLOAT_LITERAL] |= set(
                    literals[Deps.FLOAT_LITERAL])
                self.literals[Deps.CHAR_LITERAL] |= set(
                    literals[Deps.CHAR_LITERAL])
                self.literals[Deps.STRING_LITERAL] |= set(
                    literals[Deps.STRING_LITERAL])

        for f_id in function_ids:
            f = self.dbops.fnidmap[f_id]
            if f and "literals" in f:
                literals = f["literals"]
                self.literals[Deps.INT_LITERAL] |= set(
                    literals[Deps.INT_LITERAL])
                self.literals[Deps.FLOAT_LITERAL] |= set(
                    literals[Deps.FLOAT_LITERAL])
                self.literals[Deps.CHAR_LITERAL] |= set(
                    literals[Deps.CHAR_LITERAL])
                self.literals[Deps.STRING_LITERAL] |= set(
                    literals[Deps.STRING_LITERAL])

            # in addition to literals, we are going to extract constatnt values from switch info
            if f and "switches" in f:
                for s in f["switches"]:
                    for c in s["cases"]:
                        # the int value can be found at c[0]
                        try:
                            self.literals[Deps.INT_LITERAL].add(int(c[0]))
                        except Exception:
                            logging.error(
                                f"Switch error detected in function {f['name']}")
                        if len(c) == 8:
                            # we have the range-based case - the next value is at c[4]
                            try:
                                self.literals[Deps.INT_LITERAL].add(int(c[4]))
                            except Exception:
                                logging.error(
                                    f"Switch error detected in function {f['name']}")

        # finally, we can generate a dictionary file with literals
        with open(f"{self.args.output_dir}/{Deps.AOT_LITERALS_FILE}", "w") as f:
            i = 0
            _str = ""
            for l in self.literals[Deps.INT_LITERAL]:
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
                hex_str = "".join(
                    reversed([hex_str[j:j+2] for j in range(0, len(hex_str), 2)]))
                hex_str = re.sub("(..)", r"\\x\1", hex_str)
                if len(hex_str) == 0:
                    continue
                _str += f"literal{i}=\"{hex_str}\"\n"
                i += 1
            for l in self.literals[Deps.FLOAT_LITERAL]:
                # thanks to https://stackoverflow.com/questions/23624212/how-to-convert-a-float-into-hex/38879403
                hex_str = hex(struct.unpack('<Q', struct.pack('<d', l))[0])
                hex_str = hex_str.replace("L", "")
                if len(hex_str) % 2:
                    hex_str = hex_str.replace("0x", "0x0")
                hex_str = hex_str.replace("0x", "")
                # reverse bytes for little-endian
                hex_str = "".join(
                    reversed([hex_str[j:j+2] for j in range(0, len(hex_str), 2)]))
                hex_str = re.sub("(..)", r"\\x\1", hex_str)
                if len(hex_str) == 0:
                    continue
                _str += f"literal{i}=\"{hex_str}\"\n"
                i += 1
            for l in self.literals[Deps.CHAR_LITERAL]:
                if len(str(l)) == 0:
                    continue
                _str += f"literal{i}=\"{str(l)}\"\n"
                i += 1
            for l in self.literals[Deps.STRING_LITERAL]:
                if len(str(l)) <= Deps.MAX_STRING_LITERAL_LEN and len(str(l)) > 0:
                    raw = repr(l)[1:-1]
                    if "%" not in raw:
                        raw = raw.replace("\\", "\\\\")
                        _str += f"literal{i}=\"" + raw + "\"\n"
                        i += 1
            f.write(_str)

    # -------------------------------------------------------------------------

    # @belonds: deps?
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
    # @belongs: deps?
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

    # @belongs: deps or dbops
    def _get_types_recursive(self, types, base_types=None, internal_defs=None):
        if self.args.used_types_only:
            all_types = self.dbops._get_recursive_by_id(
                "types", types, "usedrefs", base_types)
        else:
            all_types = self.dbops._get_recursive_by_id(
                "types", types, "refs", base_types)
        logging.debug("Getting type deps for {} types".format(len(all_types)))
        # since the order is not guaranteed 
        # we need to perform a topological sort
        deps = {}
        _internal_defs = set()
        all_types_data = self.dbops.typemap.get_many(list(all_types))

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
            refs_types = self.dbops.typemap.get_many(list(refs))

            for r in refs_types:
                tmp = r  # self.dbops.typemap[r]
                if tmp["class"] == "pointer":
                    # logging.info("pointer")
                    # remove pointers to structs and enums from deps
                    dst = tmp["refs"]
                    if len(dst) != 1:
                        logging.warning(
                            "Expected exactly one ref for a pointer")
                        continue
                    dst_type = self.dbops.typemap[dst[0]]

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

        circles = True
        while circles:
            try:
                sorted = toposort_flatten(deps)
                circles = False
            except CircularDependencyError as e:
                logging.warning("Circular depdencies detected")

                # typedefs are known to cause circular deps problem
                # because it's hard to find a generic rule for cicles removal,
                # we decided to remove deps on toposort failure

                for tid, tid_deps in e.data.items():
                    type = self.dbops.typemap[tid]
                    if type["class"] == "typedef":
                        dst_tid = type["refs"][0]
                        dst_type = self.dbops.typemap[dst_tid]
                        dst_class = dst_type["class"]
                        if dst_class == "record" or dst_class == "enum":
                            dst_tid = dst_type["id"]
                            if dst_tid in tid_deps or dst_tid in deps[tid]:
                                deps[tid].remove(dst_tid)                                
                                logging.info(
                                    "Breaking dependency from {} to {}".format(tid, dst_tid))
                                # after removing the dependency we should explicitly add
                                # the destination of the typedef to all types dependent on 
                                # typedef
                                to_check = []
                                for _tid in deps:
                                    _type = self.dbops.typemap[_tid]
                                    if _type['class'] == 'record' or _type['class'] == 'enum':
                                        if tid in deps[_tid] and dst_tid not in deps[_tid]:
                                            logging.debug(f"adding dep {_tid} => {dst_tid}")
                                            deps[_tid].add(dst_tid)
                                            if _tid in _internal_defs:
                                                to_check.append(_tid)
                                # if the types we added deps to are internal we need to find their outer types and 
                                # add deps there 
                                while (len(to_check) > 0):
                                    _tid_ext = to_check.pop()
                                    if _tid_ext in self.internal_types:
                                        for _tid in self.internal_types[_tid_ext]:
                                            deps[_tid].add(dst_tid)
                                            logging.debug(f"adding dep {_tid} => {dst_tid}")
                                            if _tid in _internal_defs:
                                                to_check.append(_tid)
                    elif type["class"] == "function":
                        # if we are dealing with function type we don't really need to have
                        # the definitions until the function is actually used
                        for t_id in tid_deps:
                            dst_type = self.dbops.typemap[t_id]
                            dst_class = dst_type["class"]
                            if dst_class == "record" or dst_class == "enum":
                                deps[tid].remove(t_id)
                                logging.info(
                                    "Breaking dependency from {} to {}".format(tid, t_id))

                logging.info("Retry toposort after circle removal")
                #sorted = toposort_flatten(deps)
                
        sorted_types = self.dbops.typemap.get_many(list(sorted))
        sorted = [t["id"] for t in sorted_types if t["class"] != "builtin"
                  and t["id"] not in _internal_defs]
        logging.debug("sorted is {}".format(sorted))

        del sorted_types

        # adding type deps might have added types that we don't want to have
        # those are defined in base_types and need to be filtered out
        if base_types is not None:
            sorted = [t for t in sorted if t not in base_types]

        if internal_defs is not None:
            internal_defs |= _internal_defs

        return sorted, deps

    # -------------------------------------------------------------------------

    # @functions: all the functions present in the generated code
    # @belongs: deps or dbops
    def _get_types_in_funcs(self, functions, internal_defs, types_only=False):
        _internal_defs = set()

        ftypes = set()
        for f in functions:
            # types we're interested in are coming from
            # - all the variables used in the function's body
            # - function params and return type
            f_obj = self.dbops.fnidmap[f]

            if f_obj is not None:
                if types_only is False:
                    if f not in self.cutoff.external_funcs:
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
                f_obj = self.dbops.fdmap[f]
                if f_obj is None:
                    logging.error(
                        "Unable to find func or funcdecl for id {}".format(f))
                    continue
                    # sys.exit(1)
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
    # @belongs: deps or dbops
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
                    cutoff = set(self.dbops.known_funcs_ids)
                    logging.debug(f"Will use {len(cutoff)} known ids")
                    if 0 == len(cutoff):
                        cutoff = None
                else:
                    cutoff = None

                if not self.args.include_asm:
                    if cutoff is None:
                        cutoff = set()
                    # if we don't want to include assembly, we can cut the serach short
                    # whenever a function with inline asm is encountered
                    cutoff |= self.dbops.all_funcs_with_asm

                logging.debug("fcalls size is {}".format(len(fcalls)))

            used_map_name = 'funcs_tree_'
            if cutoff:
                used_map_name += 'calls' if calls_only else 'funrefs'
                if filter_on:
                    used_map_name += '_no_known'
                if not self.args.include_asm or not filter_on:
                    used_map_name += '_no_asm'
            else:
                used_map_name += 'func_calls' if calls_only else 'func_refs'
            logging.debug("selecting cache matrix based on:")
            logging.debug(" calls_only - {}; cutoff - {}; filter_on - {}; include_asm {}".format(
                calls_only, cutoff, filter_on, self.args.include_asm))
            used_map = self.dbops.get_cache_matrix(used_map_name)
            if used_map is None:
                raise Exception(f"Map {used_map_name} doesn't exist")

            # collect list of accesible functions
            if additional_refs is None:
                result = []
                # if f in used_map:
                # result = used_map[f]["funrefs"]
                result = self.dbops._graph_dfs(used_map, f)
                if f not in result:
                    result.append(f)
            else:
                tmp = set()
                for f_id in additional_refs:
                    tmp |= set(self.dbops._graph_dfs(used_map, f_id))
                    # if f_id in used_map:
                    #    tmp |= set(used_map[f_id]["funrefs"])
                    tmp.add(f_id)
                # tmp |= set(used_map[f]["funrefs"])
                tmp |= set(self.dbops._graph_dfs(used_map, f))

                tmp.add(f)

                result = list(tmp)
            for r in result:
                fcalls.add(r)

        functions |= fcalls

        func_ids = [f for f in functions]
        for func in self.dbops.fnidmap.get_many(func_ids):
            if func is not None:
                # some of the funrefs might be funcdels rather then functions
                if not calls_only:
                    fcalls |= set(func["funrefs"])
                else:
                    fcalls |= set(func["calls"])

        functions |= fcalls

        if filter_on:
            logging.debug(f"functions size before filtering {len(functions)}")
            # filter out knonw functions before returning results
            if discover_known:
                self._discover_known_functions(functions)
            self._filter_out_known_functions(functions)
            logging.debug(f"functions size after filtering {len(functions)}")

        self._filter_out_builtin_functions(functions)

        return functions

    # @types: the types we aleady know about
    # @belongs: codegen/deps
    # @sam (but see todo below)
    # @todo: this function shwould really be split in two : one that establishes types and the other responsible purely for codegen
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

        # for static inline functions we will have external stubs in a non-stub file
        # but since the functions are external we do not want to get the globals
        func_ids = [f for f in functions if (f not in self.cutoff.external_funcs and f not in self.dbops.known_funcs_ids)]
        for func in self.dbops.fnidmap.get_many(func_ids):
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
        for g in self.dbops.globalsidmap.get_many(list(globals_ids)):
            g_id = g['id']
            g_tid = g["type"]
            g_fid = g["fid"]
            # make sure that the type is not already there
            if g_tid not in types:
                globalTypes.add(g_tid)

            if "decls" in g:
                decl_tids, read_tid = self.dbops._get_global_decl_types(
                    g["decls"], g["refs"], g_tid)
                global_type_decls |= decl_tids
                internal_defs |= decl_tids

            local = True
            if (file is not None) and (g_fid != file):
                local = False

            def_str = g["def"]
            if self.args.dynamic_init:
                # Remove the 'const' qualifier from global variables when dynamic initialization is used
                def_str = self.codegen._vardecl_remove_const_qualifier(def_str)
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
                if self.args.dynamic_init:
                    def_string = "\n{};\n".format(g["def"].replace(
                        "extern ", "").replace("const ", ""))
                    g_trigger_name = "%s" % (g["hash"].replace(
                        "/", "__").replace(".", "____").replace("-", "___"))
                    g_type = self.dbops.typemap[g["type"]]
                    g_address_specifier = '&' if g_type["class"] != "const_array" and g_type[
                        "class"] != "incomplete_array" else ''
                    def_string += "\n{};\n".format(Deps.DYNAMIC_INIT_GLOBAL_VARIABLE_TEMPLATE.format(
                        g["hash"], g_address_specifier, g["name"], g_trigger_name))
                else:
                    def_string = "\n{};\n".format(
                        g["def"].replace("extern ", ""))
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
            g = self.dbops.globalsidmap[g_id]
            g_tid = g["type"]
            g_fid = g["fid"]
            # make sure that the type is not already there
            if g_tid not in types:
                globalTypes.add(g_tid)

            if "decls" in g:
                decl_tids, read_tid = self.dbops._get_global_decl_types(
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

        if type_decls is not None and internal_defs is not None:
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

    # @belongs: codegen
    # @todo: this function is only used in _get_global_types, in the part that should really
    # be moved to the codegen module
    def _adjust_varlen_decl(self, g_tid, decl):
        # handle a special case when global is a var-length array
        # in these cases we need to concretize the length for the declaration
        # this is needed in order to prevent type incompleteness errors when the
        # global would be used before it's defined (and remember that we don't do toposort)
        g_type = self.dbops.typemap[g_tid]
        if g_type["class"] == "const_array":
            size_total = int(g_type["size"])

            # let's find the size of the array type
            # be careful: if the immediate type is typedef, we will need to
            # find a concrete type as typedefs' size is 0
            # refs should have just one element: type of the member
            items_tid = g_type["refs"][0]
            items_type = self.dbops.typemap[items_tid]
            items_type = self.dbops._get_typedef_dst(items_type)
            size_item = int(items_type["size"])
            if size_item != 0:
                items_count = size_total // size_item
                decl = decl.replace("[]", f"[{items_count}]")
        return decl
