#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

#
# Cut-off module
#

import logging
import os
from typing import Optional, Set


class CutOff:

    # cut-off algorithm
    CUT_OFF_NONE = 'none'
    CUT_OFF_FUNCTIONS = 'functions'
    CUT_OFF_MODULE = 'module'
    CUT_OFF_DIRS = 'dirs'
    CUT_OFF_FILES = 'files'
    CUT_OFF_NAMED_MODULES = 'named_modules'  # currently unsupported

    # function stats details
    FUNC_STATS_BASIC = 'basic'
    FUNC_STATS_DETAILED = 'detailed'

    def __init__(self, dbops, args, deps):
        self.dbops = dbops
        self.args = args
        self.deps = deps

        self.co_funcs = set(args.co_funcs)
        self.co_dirs = set(args.co_dirs)
        self.co_modules = set(args.co_modules)
        self.co_files = set(args.co_files)

        # the set of functions that we wish to emit the code for
        self.internal_funcs = set()

        # the set of a "front" of external functions, i.e. first functions that are outside
        # of what is considered to be an off-target border
        self.external_funcs = set()

        self.fid_to_mods = {}  # map functions -> modules
        self.fid_to_dirs = {}  # map functions -> source directories

        # cache to limit the number of expensive recursive queries
        self.stats_cache = {}

    # -------------------------------------------------------------------------

    # given a function, find (recursively) all functions that is calls which are inside
    # same module; this is done with the use of information from BAS
    # @belongs: cut-off

    def _get_internal_funcs(self, f, internal_funcs, external_funcs):
        base_fid = f["id"]

        if not self.args.include_asm and base_fid in self.dbops.all_funcs_with_asm:
            logging.info(
                f"Skipping further exploration for a function with asm: {self.dbops._get_function_name(base_fid)}")
            return
        if base_fid in self.dbops.known_funcs_ids:
            logging.info("Skipping further exploration for a known function")
            return

        logging.debug("Processing function {}".format(base_fid))
        funrefs = set(f["funrefs"])

        # in additiom to funrefs, there might be an implicit dependency to other functions
        # coming from globals and types
        internal_defs = set()
        type_refs = self.deps._get_types_in_funcs([base_fid], internal_defs)
        # skip_list = set(f)
        # skip_list |= internal_funcs
        # skip_list |= external_funcs
        funrefs |= self.deps._get_funcs_from_types(type_refs)  # , skip_list)

        global_refs = set()
        if "globalrefs" in f:
            global_refs |= set(f["globalrefs"])
        global_refs |= self.deps._get_globals_from_types(type_refs)
        global_refs |= self.deps._get_globals_from_globals(global_refs)

        funrefs |= self.deps._get_funcs_from_globals(global_refs)

        # gather func pointers
        fptrs = self._get_infer_function(base_fid)
        if fptrs is not None:
            for expr in fptrs:
                funrefs.update([f_id for f_id in expr[1]])

        for fid in funrefs:
            logging.debug("checking funref {} ".format(fid))
            ext = False  # deciding if the function is external or not

            fname = ""
            f = self.dbops.fnidmap[fid]
            if f is not None:
                fname = f['name']
            if fid in self.dbops.always_inc_funcs_ids:
                logging.info(f"Including internal func {fid}")
            elif fid in self.dbops.known_funcs_ids:
                logging.info(f"{fid} {fname} is a known function")
            else:
                if self.args.cut_off == CutOff.CUT_OFF_MODULE:
                    if fid not in self.fid_to_mods:
                        ext = True
                        # fid will not be in fid_to_mods if it's an unresolved function in db.json
                    else:
                        # internal functions are the ones residing in the same module

                        if base_fid not in self.fid_to_mods:
                            self._get_mods_and_dirs_for_f(base_fid)

                        mods = self.fid_to_mods[fid]

                        base_mods = self.fid_to_mods[base_fid]
                        # let's check if the modules are the same
                        # in principle we need to make sure that every module the base is compiled in,
                        # is alos on the function's list of modules
                        if 0 != len(base_mods.difference(mods)):
                            ext = True
                elif self.args.cut_off == CutOff.CUT_OFF_DIRS:
                    if fid not in self.fid_to_dirs:
                        ext = True
                        # fid will not be in fid_to_dirs if it's an unresolved function (see dbops._get_function_file)
                    else:
                        # internal functions are the ones residing in the specified dirs
                        dirs = self.fid_to_dirs[fid]
                        # it is enough that one of the function's dirs is on the co_dirs list
                        if len(dirs.difference(self.co_dirs)) == len(dirs):
                            ext = True

                elif self.args.cut_off == CutOff.CUT_OFF_FUNCTIONS:
                    # internal functions are the ones with names on the list
                    name = self.dbops._get_function_name(fid)
                    if name not in self.co_funcs:
                        ext = True

                elif self.args.cut_off == CutOff.CUT_OFF_FILES:
                    # internal functions are the ones that reside in the
                    # specified source files
                    src, loc = self.dbops._get_function_file(fid)
                    if src not in self.co_files:
                        ext = True

                # if the function is external but we specify --co-dirs, --co-files
                # or --co-funcs, we check if we could pull the function in
                if ext and self.args.cut_off != CutOff.CUT_OFF_DIRS and len(self.co_dirs) > 0:
                    if fid in self.fid_to_dirs:
                        dirs = self.fid_to_dirs[fid]
                        # it is enough that one of the function's dirs is on the co_dirs list
                        if len(dirs.difference(self.co_dirs)) != len(dirs):
                            ext = False

                if ext and self.args.cut_off != CutOff.CUT_OFF_FUNCTIONS and len(self.co_funcs) > 0:
                    # internal functions are the ones with names on the list
                    name = self.dbops._get_function_name(fid)
                    if name in self.co_funcs:
                        ext = False

                if ext and self.args.cut_off != CutOff.CUT_OFF_FILES and len(self.co_files) > 0:
                    # internal functions are the ones that reside in the
                    # specified source files
                    src, loc = self.dbops._get_function_file(fid)
                    if src in self.co_files:
                        ext = False

            if ext:
                # logging.debug(
                #    "Function {} is outside of base module {}".format(fid, base_fid))
                external_funcs.add(fid)
            else:
                # logging.debug(
                #    "Function {} is inside of base module {}".format(fid, base_fid))
                tmp_f = self.dbops.fnidmap[fid]
                if tmp_f is None and fid not in self.dbops.known_funcs_ids:
                    # we've hit an unresolved function or a funcdecl
                    external_funcs.add(fid)
                    continue
                if fid not in internal_funcs:
                    internal_funcs.add(fid)
                    if tmp_f is not None:
                        self._get_internal_funcs(
                            tmp_f, internal_funcs, external_funcs)

    # -------------------------------------------------------------------------

    #
    # Queries pre-processed map of function pointers matches
    #  Returns the following list:
    #       [("expr", [func_id_0, func_id_1, ...])] or None if ID not found
    #    where,
    #       func_id_<num>: function id that could be possible stored
    #                      (and invoked) through the pointer
    #
    #       expr: the expression of the function invocation through a pointer
    #
    #  Arguments:
    #       func_id: ID of the function for which function_pointers should
    #                be found
    def _get_infer_function(self, func_id: int) -> Optional[list]:
        if func_id not in self.dbops.fpointer_map:
            return None
        return self.dbops.fpointer_map[func_id]['entries']

    # -------------------------------------------------------------------------

    def _get_mods_and_dirs_for_f(self, fid):
        if fid in self.fid_to_mods:
            # this has already been executed for this function
            return

        src, loc = self.dbops._get_function_file(fid)
        mod_paths = None

        # Cut-off based on modules
        if (src is None) and (loc is None):
            # that is for the unresolved functions
            mod_paths = ["/tmp/no_such_mod"]
        else:
            data = self.dbops.rdm_data[loc]

            if data is None:
                logging.warning(f"cannot find {loc} in rdm database")
                mod_paths = []
            else:
                mod_paths = data["entries"]

        self.fid_to_mods[fid] = set(mod_paths)

        # cut-off based on the list of function names
        # we don't really need to collect anything in that case - we will filter out
        # based on names

        # cut-off based on the list of directories
        if src is not None:
            self.fid_to_dirs[fid] = {os.path.dirname(src)}
        else:
            self.fid_to_dirs[fid] = {"/tmp/no_such_file"}

    # @base_fids: the ids of the functions we would like to create an off-target for
    # @fids: the ids of all the other functions (that we discovered recursively)
    # @belongs: deps or cut-off
    def _get_function_stats(self, base_fids, fids):
        base_functions = self.dbops.fnidmap.get_many(list(base_fids))

        # by default we'll add the dirs in which the base functions reside
        # to the list of allowed funcs
        # by default we'll add the names of the base functions
        # to the list of allowed funcs
        # by default we'll add the files in which base functions are defined
        # to the list of allowed funcs

        for f in base_functions:
            self.co_funcs.add(f["name"])

        logging.info(f"co_dirs is {self.co_dirs}")

        for fid in fids:
            self._get_mods_and_dirs_for_f(fid)

        self.internal_funcs = set()
        self.external_funcs = set()
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

        for fid in self.external_funcs:
            f = self.dbops.fnidmap[fid]
            if f is None:
                continue
            if self.args.func_stats == CutOff.FUNC_STATS_DETAILED:
                # let's check how many functions would that function pull in
                query = set()
                query.add(fid)

                if fid not in self.stats_cache:
                    self.deps._get_called_functions(query)
                    self.stats_cache[fid] = query
            else:
                subtree_count = -1
                if fid not in self.stats_cache:
                    # let's see if we can tell whether the function doesn't call
                    # any others
                    if "funrefs" not in f or len(f["funrefs"]) == 0:
                        self.stats_cache[fid] = set([fid])
                    else:
                        funcs = set(f["funrefs"])
                        self.deps._discover_known_functions(funcs)
                        self.deps._filter_out_known_functions(funcs)
                        self.deps._filter_out_builtin_functions(funcs)
                        if len(funcs) == 0:
                            subtree_count = 0
                        else:
                            found = False
                            for id in funcs:
                                if id in self.dbops.fnidmap:
                                    found = True
                                    # at least one of the called functions is a func
                                    break

                            if not found:
                                # all of the called functions are either funcdecls or unresolved
                                # which will be external anyway
                                subtree_count = 0

                        if subtree_count == 0:
                            self.stats_cache[fid] = set([fid])

    def _print_function_stats(self):
        logging.info("Printing internal functions:")
        for fid in self.internal_funcs:
            f = self.dbops.fnidmap[fid]
            if f is not None:
                logging.info(
                    "- [internal] {} @ {}".format(f["name"], f["location"]))

        logging.info("Printing first external functions:")
        for fid in self.external_funcs:
            f = self.dbops.fnidmap[fid]
            if f is None:
                # if it's not a function (funcdecl or unresovled), we wouldn't know how many others it calls
                # try in funcdecls functions
                f = self.dbops.fdmap[fid]
                if f is None:
                    # try in unresolved
                    f = self.dbops.umap[fid]
                    logging.info("- [external] {}".format(f["name"]))
                else:
                    logging.info("- [external] {}".format(fid))
                continue
            if self.args.func_stats == CutOff.FUNC_STATS_DETAILED:
                # let's check how many functions would that function pull in
                query = set()
                query.add(fid)
                if fid not in self.stats_cache:
                    self.deps._get_called_functions(query)
                    self.stats_cache[fid] = query
                query |= self.stats_cache[fid]
                
                logging.info("- [external] {} @ {} pulls in another {} functions".format(
                    f["name"], f["location"], len(query) - 1))
            else:
                subtree_count = -1
                if fid in self.stats_cache:
                    # if we are in the basic stats mode, only functions known to not call any other
                    # will be added to stats_cache, which means that the number of called functions is 0
                    subtree_count = 0
                if subtree_count == -1:
                    logging.info(
                        "- [external] {} @ {}".format(f["name"], f["location"]))
                else:
                    logging.info("- [external] {} @ {} pulls in another {} functions".format(
                        f["name"], f["location"], subtree_count))
