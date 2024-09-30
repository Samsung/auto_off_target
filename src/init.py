#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

#
# Init module
#

import logging
import sys
import copy
import functools
import json

class TypeUse:

    instance_id = 0

    def __init__(self, t_id, original_tid, is_pointer):
        self.id = TypeUse.instance_id
        TypeUse.instance_id += 1
        self.t_id = t_id  # the last known type of this object
        self.original_tid = original_tid
        self.is_pointer = is_pointer
        self.name = ""
        self.cast_types = []  # a list of all known types for this object
        # a list of tuples (containig type TypeUse, member number)
        self.offsetof_types = []
        # a reverse relationship to the types that were used in the offsetof
        # operator to retrieve this type
        # a list of tuples (member number, TypeUse object)
        self.contained_types = []
        # note: this list has a precedence over used_members when it
        # comes to init
        self.used_members = {}  # for a given type, maps used member of that type
        # to the related TypeUse objects

    def __str__(self):
        return f"[TypeUse] id = {self.id} t_id = {self.t_id} original_tid = {self.original_tid} " +\
            f"is_pointer = {self.is_pointer} name = '{self.name}' offsetof_types = {self.offsetof_types} " +\
            f"contained_types = {self.contained_types} used_members = {self.used_members} cast_types = {self.cast_types}"

    def __repr__(self):
        return f"[TypeUse id={self.id} t_id={self.t_id} original_tid={self.original_tid}]"


class _TreeIterator:
    """
    Class for iterating derefs_trace tree.
    derefs_trace is a list that contains elements and subtrees
    ex. [(a, b), [(c, d), [(e, f), (g, h)], (i, j)]] represents
    [(a, b), (c, d), (e, f), (g, h), (i, j)]
    """

    def __init__(self, tree):
        self.tree = tree
        self.index = 0
        self.next_iterator = None

    def __iter__(self):
        return self

    def len(self, tree_length_cache=None):
        if tree_length_cache is None:
            tree_length_cache = {}
        if id(self.tree) in tree_length_cache:
            return tree_length_cache[id(self.tree)]

        s = 0
        for v in self.tree:
            if not isinstance(v, list):
                s += 1
            else:
                s += _TreeIterator(v).len(tree_length_cache)

        tree_length_cache[id(self.tree)] = s
        return s

    def __next__(self):
        if self.index >= len(self.tree):
            raise StopIteration

        if not isinstance(self.tree[self.index], list):
            r = self.tree[self.index]
            self.index += 1
            return r

        if not self.next_iterator:
            self.next_iterator = _TreeIterator(self.tree[self.index])

        try:
            return self.next_iterator.__next__()
        except StopIteration:
            self.next_iterator = None
            self.index += 1
            return self.__next__()


class _DerefsEntry:

    def __init__(self, deref):
        self.deref = deref
        self.cast_data = None
        self.offsetof_data = None
        self.member_data = None
        self.access_order = None

    def init_data(self, init, f):
        self.cast_data = init._get_cast_from_deref(self.deref, f)
        if self.cast_data is not None:
            return

        self.offsetof_data = init._get_offsetof_from_deref(self.deref)
        if self.offsetof_data is not None:
            return

        self.member_data, self.access_order = init._get_member_access_from_deref(self.deref)

    def no_data(self):
        return self.cast_data is None and \
            self.offsetof_data is None and \
            self.member_data is None

    def __iter__(self):
        return iter((self.deref, self.cast_data, self.offsetof_data, self.member_data, self.access_order))


class Init:

    CAST_PTR_NO_MEMBER = -1
    MAX_RECURSION_DEPTH = 50

    INIT_CL_NONPTR = "nonptr"
    INIT_CL_PTR = "ptr"
    INIT_CL_FPTR = "fptr"
    INIT_CL_OFFSETOF = "offsetof"

    def __init__(self, dbops, cutoff, deps, codegen, args):
        self.dbops = dbops
        self.cutoff = cutoff
        self.deps = deps
        self.codegen = codegen
        self.args = args
        self.member_usage_info = {}
        self.casted_pointers = {}
        self.offset_pointers = {}
        self.trace_cache = {}
        self.derefs_cache = {}
        self.obj_match_cache = {}
        self.ptr_init_size = 1  # when initializing pointers use this a the number of objects
        self.array_init_max_size = 32  # when initializing arrays use this a an upper limimit
        self.tagged_vars_count = 0
        self.fpointer_stubs = []
        self.stub_names = set()
        self.init_data = {}
        self.init_data["globals"] = []
        self.init_data["funcs"] = []

    # -------------------------------------------------------------------------

    # the aim of this function is to iterate through all types and within record types
    # find those that contain pointers
    # then, further analysis is performed to check if we can match the pointer member with
    # a corresponding size member
    # @belongs: init

    def _analyze_types(self):
        logging.info("Beginning type analysis")

        self._generate_member_size_info(
            self.dbops.fnmap.get_all(), self.dbops.typemap.get_all())

        logging.info(
            f"Type analysis complete. We captured data for {len(self.member_usage_info)} types")
        self._print_member_size_info()

        # records_with_pointers = {}

        # checked_record_types = 0
        # for t in self.dbops.db["types"]:
        #     if t["class"] == "record":
        #         checked_record_types += 1
        #         member_id = 0
        #         for t_id in t["refs"]:
        #             ref_t = self.dbops.typemap[t_id]
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
        #     t = self.dbops.typemap[t_id]
        #     member_id = 0
        #     matches = set()
        #     for ref_id in t["refs"]:
        #         ref_t = self.dbops.typemap[ref_id]
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
    # @belongs: init
    def _print_member_size_info(self):
        count = 0
        logging.info(f"We have info for {len(self.member_usage_info)} structs")
        for t_id in self.member_usage_info:
            name = self.dbops.typemap[t_id]["str"]
            logging.info(f"Struct : {name} ")
            index = 0
            for member in self.member_usage_info[t_id]:
                if len(member) > 0:
                    count += 1
                    logging.info(
                        f"\tWe have some data for member {self.dbops.typemap[t_id]['refnames'][index]}")
                    if "value" in member:
                        logging.info(f"\t\tvalue: {member['value']}")
                    elif "member_idx" in member:
                        done = False
                        for m in member['member_idx']:
                            done = True
                            name = self.dbops.typemap[t_id]['refnames'][m]
                            logging.info(f"\t\tmember_idx: {name}")
                        if not done:
                            logging.info(
                                f"detected member_idx: {member['member_idx']}")

                    elif "name_size" in member:
                        done = False
                        for m in member['name_size']:
                            done = True
                            name = self.dbops.typemap[t_id]['refnames'][m]
                            logging.info(f"\t\tname_size: {name}")
                        if not done:
                            logging.info(
                                f"datected name_size: {member['name_size']}")
                    else:
                        logging.info(f"\t\tPrinting raw data {member}")
                index += 1

        logging.info(
            f"We have found {count} structs with some info on array sizes")

    # @belongs: init
    def _generate_constraints_check(self, var_name, size_constraints):
        str = ""
        if "min_val" in size_constraints:
            str += f"#ifndef KLEE\n"
            
            str += f"if ({var_name} < {size_constraints['min_val']})" + "{\n"
            str += f"\taot_memory_setint(&{var_name}, {size_constraints['min_val']});\n"
            str += "}\n"
            
            str += "#else\n"
            
            str += f"klee_assume({var_name} >= {size_constraints['min_val']});\n"
            
            str += "#endif\n"
        if "max_val" in size_constraints:
            str += f"#ifndef KLEE\n"
            
            str += f"if ({var_name} > {size_constraints['max_val']})" + "{\n"
            max_val_int = int(size_constraints['max_val'])            
            if max_val_int != 0:
                str += f"\taot_memory_setint(&{var_name}, ({var_name} % {size_constraints['max_val']}) + 1);\n"
            else:
                str += f"\taot_memory_setint(&{var_name}, 0);\n"
            str += "}\n"

            str += "#else\n"

            str += f"klee_assume({var_name} <= {size_constraints['max_val']});\n"
            
            str += "#endif\n"
        return str

    # use member_type_info to get the right member init ordering for a record type
    # return a list consisting of member indices to generate init for
    # @belongs: init
    def _get_members_order(self, t, subitems=None):
        ret = []
        ret_user = []
        size_constraints = []
        if t['class'] != 'record':
            return None, None
        ret = [i for i in range(len(t['refnames']))]
        if subitems != None:
            ret_user = [0 for i in range(len(subitems))]
        size_constraints = [{} for i in range(len(t['refnames']))]

        t_id = t['id']

        if t_id not in self.member_usage_info:
            return ret, size_constraints

        fields_no = len(t['refnames'])
        for i in range(fields_no):
            field_name = t['refnames'][i]

            if field_name == "__!attribute__" or field_name == "__!anonrecord__" or \
                    field_name == "__!recorddecl__" or field_name == "__!anonenum__":
                continue

            if subitems != None and field_name in subitems:
                ret[i] = -1
                ret_user[subitems.index(field_name)] = i
                i += 1
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
                        size_member_index = [size_member_index]

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
                                            # leverage the fact that we noticed array reference at a concrete offset
                                            max_val = val
                                size_constraints[size_member_index]["max_val"] = max_val
                            size_member_index = [size_member_index]

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
                                            # leverage the fact that we noticed array reference at a concrete offset
                                            max_val = val
                                size_constraints[size_member_index]["max_val"] = max_val
                            size_member_index = [size_member_index]

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
                            logging.info(
                                f"Swapping members {current_index} and {sm_index} in type {t['str']}")
                            current_index = sm_index

                if "index" in usage_info:
                    logging.info(
                        f"Index detected in usage info for member {field_name}")
                    max_val = -1
                    if "max_val" in size_constraints[i]:
                        max_val = size_constraints[i]["max_val"]
                    if (max_val == -1) or ((usage_info["index"] - 1) < max_val):
                        # the 'index' member is collected based on a const-size array reference
                        # therefore if one exists, we are certain that the value is no greater than the size - 1
                        size_constraints[i]["max_val"] = usage_info["index"] - 1

                        if "min_val" not in size_constraints:
                            size_constraints[i]["min_val"] = 0

        if ret_user != []:
            ret_tmp = ret_user + ret
            index = 0
            for i in ret_tmp:
                if i == -1:
                    continue
                ret[index] = i
                index += 1

        return ret, size_constraints

    # @belongs: init
    def _is_size_type(self, t):
        ints = {'char', 'signed char', 'unsigned char', 'short', 'unsigned short', 'int', 'unsigned int',
                'long', 'unsigned long', 'long long', 'unsigned long long', 'unsigned __int128'}
        t = self.dbops._get_typedef_dst(t)
        if t["str"] in ints:
            return True
        return False

    # @belongs: init
    def _get_record_type(self, base_type):
        # remove typedef to pointer type
        base_type = self.dbops._get_typedef_dst(base_type)
        # remove pointer
        base_type = self.dbops.typemap[self.dbops._get_real_type(
            base_type['id'])]
        # remove typedef to record type)
        base_type = self.dbops._get_typedef_dst(base_type)
        return base_type

    # @belongs: init but unused
    def _find_local_init_or_assign(self, local_id, ord, func):
        matching_derefs = []
        for deref in func["derefs"]:
            if deref["kind"] in ["init", "assign"]:
                lhs = deref["offsetrefs"][0]
                if lhs["kind"] == "local" and lhs["id"] == local_id and deref["ord"] < ord:
                    matching_derefs.append(deref)
        return matching_derefs

    # @belongs: init
    def _is_pointer_like_type(self, t):
        t = self.dbops._get_typedef_dst(t)
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
    # @belongs: init
    def _generate_member_size_info(self, funcs, types):
        logging.info(f"will generate size info")

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
                        record_type = self._get_record_type(
                            self.dbops.typemap[member_deref["type"][-1]])
                        record_id = record_type["id"]
                        member_id = member_deref["member"][-1]
                        member_type = self.dbops.typemap[record_type["refs"][member_id]]
                        member_type = self.dbops._get_typedef_dst(member_type)
                        # we only care about poiners
                        if self._is_pointer_like_type(member_type):
                            # add info about member usage (implicit by existence)
                            if record_id not in self.member_usage_info:
                                self.member_usage_info[record_id] = [
                                    {} for k in record_type["refs"]]
                            member_data = self.member_usage_info[record_id][member_id]

                            # add info about potential size
                            if deref["offset"] != 0:
                                if "value" not in member_data:
                                    member_data["value"] = deref["offset"]+1
                                else:
                                    member_data["value"] = max(
                                        member_data["value"], deref["offset"]+1)
                            # add info about potential index member
                            for index_offsetref in deref["offsetrefs"][1:]:
                                # same base member index
                                if index_offsetref["kind"] == "member":
                                    size_deref = derefs[index_offsetref["id"]]
                                    size_record_type = self._get_record_type(
                                        self.dbops.typemap[size_deref["type"][-1]])
                                    size_record_id = size_record_type["id"]
                                    size_member_id = size_deref["member"][-1]
                                    size_member_type = self.dbops.typemap[size_record_type["refs"]
                                                                          [size_member_id]]
                                    size_member_type = self.dbops._get_typedef_dst(
                                        size_member_type)
                                    if self._is_size_type(size_member_type):
                                        if "member_idx" not in member_data:
                                            member_data["member_idx"] = set()
                                        member_data["member_idx"].add(
                                            (size_record_id, size_member_id))
                            # add info about potential size member
                            if len(deref["offsetrefs"]) == 2:
                                index_offsetref = deref["offsetrefs"][1]
                                item = next(
                                    cs for cs in func["csmap"] if cs["id"] == deref["csid"])
                                if "cf" in item and item["cf"] in ["do", "while", "for", "if"]:
                                    # find condition
                                    for cderef in derefs:
                                        if cderef["kind"] == "cond" and cderef["offset"] == deref["csid"]:
                                            if len(cderef["offsetrefs"]) == 1 and cderef["offsetrefs"][0]["kind"] == "logic":
                                                lderef = derefs[cderef["offsetrefs"][0]["id"]]
                                                if lderef["offset"] in [10, 12, 15] and len(lderef["offsetrefs"]) == 2:
                                                    if index_offsetref == lderef["offsetrefs"][0]:
                                                        size_offsetref = lderef["offsetrefs"][1]
                                                        if size_offsetref["kind"] == "integer":
                                                            size = size_offsetref["id"]
                                                            if lderef["offset"] == 12:
                                                                size += 1
                                                            if "value" not in member_data:
                                                                member_data["value"] = size
                                                            else:
                                                                member_data["value"] = max(
                                                                    member_data["value"], size)
                                                        if size_offsetref["kind"] == "member":
                                                            size_deref = derefs[size_offsetref["id"]]
                                                            size_record_type = self._get_record_type(
                                                                self.dbops.typemap[size_deref["type"][-1]])
                                                            size_record_id = size_record_type["id"]
                                                            size_member_id = size_deref["member"][-1]
                                                            size_member_type = self.dbops.typemap[
                                                                size_record_type["refs"][size_member_id]]
                                                            size_member_type = self.dbops._get_typedef_dst(
                                                                size_member_type)
                                                            if self._is_size_type(size_member_type):
                                                                if "member_size" not in member_data:
                                                                    member_data["member_size"] = set(
                                                                    )
                                                                member_data["member_size"].add(
                                                                    (size_record_id, size_member_id))
                # add info about members as index to const arrays
                if deref["kind"] == "array" and deref["basecnt"] == 1 and len(deref["offsetrefs"]) == 2:
                    base_offsetref = deref["offsetrefs"][0]
                    index_offsetref = deref["offsetrefs"][1]
                    if index_offsetref["kind"] == "member":
                        # try find array size
                        size = 0
                        if base_offsetref["kind"] == "member":
                            base_deref = derefs[base_offsetref["id"]]
                            base_record_type = self._get_record_type(
                                self.dbops.typemap[base_deref["type"][-1]])
                            base_member_id = base_deref["member"][-1]
                            base_member_type = self.dbops._get_typedef_dst(
                                self.dbops.typemap[base_record_type["refs"][base_member_id]])
                            if base_member_type["class"] == "const_array":
                                size = self._get_const_array_size(
                                    base_member_type)
                        elif base_offsetref["kind"] == "global":
                            global_deref = self.dbops.globalsidmap[base_offsetref["id"]]
                            global_type = self.dbops._get_typedef_dst(
                                self.dbops.typemap[global_deref["type"]])
                            if global_type["class"] == "const_array":
                                size = self._get_const_array_size(global_type)
                        elif base_offsetref["kind"] == "local":
                            for l in func["locals"]:
                                if l["id"] == base_offsetref["id"]:
                                    local_deref = l
                                    break
                            local_type = self.dbops._get_typedef_dst(
                                self.dbops.typemap[local_deref["type"]])
                            if local_type["class"] == "const_array":
                                size = self._get_const_array_size(local_type)
                        if size != 0:
                            # add size info
                            index_deref = derefs[index_offsetref["id"]]
                            index_record_type = self._get_record_type(
                                self.dbops.typemap[index_deref["type"][-1]])
                            index_record_id = index_record_type["id"]
                            index_member_id = index_deref["member"][-1]
                            if index_record_id not in self.member_usage_info:
                                self.member_usage_info[index_record_id] = [
                                    {} for k in index_record_type["refs"]]
                            index_data = self.member_usage_info[index_record_id][index_member_id]
                            if "index" in index_data:
                                index_data["index"] = max(
                                    size, index_data["index"])
                            index_data["index"] = size

        for _t in types:
            t = self._get_record_type(_t)
            if t["class"] == "record":
                # try guessing size member from name
                # do only once
                record_type = t
                record_id = t["id"]

                record_refs = record_type["refs"]
                record_refnames = record_type["refnames"]

                if record_id not in self.member_usage_info:
                    self.member_usage_info[record_id] = [
                        {} for k in record_refs
                    ]

                for member_id, type_id in enumerate(record_refs):
                    member_type = self.dbops.typemap[type_id]
                    # looking for a pointer struct members
                    if not self._is_pointer_like_type(member_type):
                        continue

                    member_name = record_refnames[member_id]
                    member_data = self.member_usage_info[record_id][member_id]

                    if "name_size" in member_data:
                        continue

                    sizes = set()
                    sizematch = ["size", "len", "num",
                                 "count", "sz", "n_", "cnt", "length"]
                    for size_member_id, size_type_id in enumerate(record_refs):
                        size_type = self.dbops.typemap[size_type_id]
                        if not self._is_size_type(size_type):
                            continue

                        # name matching
                        size_name = record_refnames[size_member_id]
                        if member_name not in size_name:
                            continue

                        for match in sizematch:
                            if match in size_name.replace(member_name, '').lower():
                                sizes.add(size_member_id)
                                break

                    # TODO: solve priority instead of adding all maybe
                    if len(sizes) > 1:
                        pass
                    if len(sizes) > 0:
                        member_data["name_size"] = sizes

    # -------------------------------------------------------------------------

    # Walk through pointer or array types and extract underlying record type
    # Returns (RT,TPD) pair where:
    #  RT: underlying record type
    #  TPD: if the underlying record type was a typedef this is the original typedef type
    # In case record type cannot be resolved returns (None,None) pair
    # @belongs: init?
    def _resolve_record_type(self, TID, TPD=None):

        T = self.dbops.typemap[TID]
        if T["class"] == "record" or T["class"] == "record_forward":
            return T, TPD
        elif T["class"] == "pointer" or T["class"] == "const_array" or T["class"] == "incomplete_array":
            TPD = None
            return self._resolve_record_type(T["refs"][0], TPD)
        elif T["class"] == "typedef":
            if TPD is None:
                TPD = T
            return self._resolve_record_type(T["refs"][0], TPD)
        elif T["class"] == "attributed":
            return self._resolve_record_type(T["refs"][0], TPD)
        else:
            return None, None

    # -------------------------------------------------------------------------

    # To fuzz or not to fuzz, that is the question!
    # This function decides this the same way Hamlet would do:
    # - if it's a builtin type -> we fuzz it
    # - otherwise -> don't fuzz it
    # @belongs: init
    def _to_fuzz_or_not_to_fuzz(self, t):

        cl = t["class"]

        if cl == "builtin" or cl == "enum":
            return True
        elif cl == "const_array" or cl == "incomplete_array":
            dst_type = self.dbops.typemap[t["refs"][0]]
            dst_type = self.dbops._get_typedef_dst(dst_type)
            return self._to_fuzz_or_not_to_fuzz(dst_type)

        return False

    # -------------------------------------------------------------------------

    # @belongs: init
    def _get_cast_ptr_data(self, type, member_number=CAST_PTR_NO_MEMBER):
        t_id = type["id"]
        _t_id = self.dbops._get_real_type(t_id)
        _type = self.dbops.typemap[_t_id]
        logging.debug(
            f"Getting casted data for {self.codegen._get_typename_from_type(type)}")
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
                logging.debug(
                    f"Member {member_number} not found for entry for type {t_id}")
                entry = None
        else:
            typename = self.codegen._get_typename_from_type(type)
            logging.debug(f"No cast information found for type {typename}")

        if entry is not None and member_number != Init.CAST_PTR_NO_MEMBER:
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

    # @belongs: init
    def _get_tagged_var_name(self):
        self.tagged_vars_count += 1
        return f"\"aot_var_{self.tagged_vars_count}\""
    
    # -------------------------------------------------------------------------

    # Function extracts part of the given name. If backwards is False then it extracts first 
    # subname, otherwise it extracts last subname.
    # {first subname}->{second subname}->...->{last subname}
    #
    # Function returns:
    #   index - index in given name at which we split name
    #   name_base - part of given name to the left of index
    #   name_left - part of given name to the right of index
    #   is_arrow - flag that says if we split at "." or "->"
    # @belongs: init
    def get_names_after_extraction(self, name, backwards=False):
        index_dot = (name.rfind(".") if backwards else name.find("."))
        index_arrow = (name.rfind("->") if backwards else name.find("->"))
        index = -1
        if index_dot > index_arrow:
            index = index_dot
        else:
            index = index_arrow

        name_base = ""
        name_left = ""
        is_arrow = False
        if index != -1:
            name_base = name[:index]
            if index == index_dot:
                index += 1
            else:
                index += 2
                is_arrow = True
            name_left = name[index:]

        return index, name_base, name_left, is_arrow
     
    # -------------------------------------------------------------------------

    # Function goes through init_data and its items and subitems. Its goal is to find user init data 
    # for member, that is specified in pre_name variable.
    # pre_name has a form:
    # {struct} -> {member_of_struct} -> {member_of_member_of_struct} -> ... -> {member_we_want_to_find}
    # It returns the init data for member and the name of the first struct from pre_name.
    #   (Why? The members can have only one possible name, but the name of struct can be from the list of names.)
    # @belongs: init
    def find_subitem(self, pre_name, item):
        name_base = ""
        out_name_base = ""
        name_left = pre_name
        rec_item = item

        while name_left != "":
            found_iter = False

            # extract name of struct from current level of search
            index, name_base_tmp, name_left_tmp, is_arrow = self.get_names_after_extraction(name_left)
            if index != -1:
                name_base = name_base_tmp
                name_left = name_left_tmp
            else:
                name_base = name_left
                name_left = ""

            while ")" in name_base:
                index_tmp = name_base.find(")")
                if index_tmp == len(name_base)-1:
                    name_base = name_base[:index_tmp]
                else:
                    name_base = name_base[index_tmp+1:]
            
            # find out if the name is in init_file
            if "items" in rec_item:
                out_name_base = name_base
                for entry in rec_item["items"]:
                    name_core = name_base
                    if "[" in name_base:
                        name_core = name_base[:name_base.find("[")]
                    if name_core in entry["name"]:
                        rec_item = entry
                        found_iter = True
                        break
            else: # "subitems" in rec_item
                for entry in rec_item["subitems"]:
                    name_core = name_base
                    if "[" in name_base:
                        name_core = name_base[:name_base.find("[")]
                    if name_core in entry["name"]:
                        rec_item = entry
                        found_iter = True
                        break
            
            if not found_iter:
                return None, None
            
        return rec_item, out_name_base
    
    # -------------------------------------------------------------------------

    # Function goes through init_data and its items and subitems. Its goal is to find user init data 
    # for member, that is specified in pre_name variable.
    # pre_name has a form:
    # {struct} -> {member_of_struct} -> {member_of_member_of_struct} -> ... -> {id_of_member_we_want_to_find}
    #   (Why id?
    #    We look for unnamed member, we can only identify it by id.)
    # It returns the init data for member and the name of the first struct from pre_name.
    #   (Why name of struct? 
    #    The members can have only one possible name, but the name of struct can be from the list of names.)
    # @belongs: init
    def find_hidden_subitem(self, pre_name, item):
        name_base = ""
        out_name_base = ""
        name_left = pre_name
        rec_item = item

        while name_left != "":
            found_iter = False

            # extract name of struct from current level of search
                # find index at which the name ends
            index, name_base_tmp, name_left_tmp, is_arrow = self.get_names_after_extraction(name_left)
            if index != -1:
                name_base = name_base_tmp
                name_left = name_left_tmp
            else:
                name_base = name_left
                name_left = ""

            while ")" in name_base:
                index_tmp = name_base.find(")")
                if index_tmp == len(name_base)-1:
                    name_base = name_base[:index_tmp]
                else:
                    name_base = name_base[index_tmp+1:]
            
            # find out if the name is in init_file
            if "items" in rec_item:
                out_name_base = name_base
                for entry in rec_item["items"]:
                    name_core = name_base
                    if "[" in name_base:
                        name_core = name_base[:name_base.find("[")]
                    if name_core in entry["name"]:
                        rec_item = entry
                        found_iter = True
                        break
            else: # "subitems" in rec_item
                if not name_base.isnumeric():
                    for entry in rec_item["subitems"]:
                        name_core = name_base
                        if "[" in name_base:
                            name_core = name_base[:name_base.find("[")]
                        if name_core in entry["name"]:
                            rec_item = entry
                            found_iter = True
                            break
                else: # is numeric so we look at "id" and not "name" this time
                    for entry in rec_item["subitems"]:
                        if int(name_base) == entry["id"]:
                            rec_item = entry
                            found_iter = True
                            break
            
            if not found_iter:
                return None, None
            
        return rec_item, out_name_base
    
    # -------------------------------------------------------------------------

    # Function takes name of type, iterates through data base with types and returns the type with given name (the one not being const).
    # @belongs: init
    def find_type_by_name(self, typename):
        for type in self.dbops.typemap:
            tmp_name = self.codegen._get_typename_from_type(type)
            if tmp_name == typename and ("qualifiers" not in type or 'c' not in type["qualifiers"]):
                return type
        return None

    # -------------------------------------------------------------------------
    
    # Function reads user initialization data (if it exists) for parameter that we want to initialize. It takes a few variables
    # and returns them updated after reading data.
    # @belongs: init
    def read_user_init_data(self, loop_count, null_terminate, tag, value, min_value, max_value, protected, value_dep, isPointer, fuzz_offset, user_init, fuzz,
                            is_hidden, version, entity_name, is_subitem, level, fid, type, name, typename, subitems_names, hidden_members,
                            always_init, cast_str):
        
        if not is_hidden and version:
            fuzz = int(self._to_fuzz_or_not_to_fuzz(type))
            typename = self.codegen._get_typename_from_type(type)
            if typename in ["struct", "enum", "union"]:  # annonymous type
                typename = name

        entity_name_core = entity_name
        if entity_name is not None and "[" in entity_name:
            entity_name_core = entity_name[:entity_name.find("[")]

        if self.dbops.init_data is not None and (entity_name_core in self.dbops.init_data) \
            and (level == 0 or self.dbops.init_data[entity_name_core]["interface"] == "global" or is_subitem):

            if self.args.debug_vars_init:
                logging.info(
                    f"Detected that {entity_name} has user-provided init")
                
            item = self.dbops.init_data[entity_name_core]
            for entry in item["items"]:
                entry_type = "unknown"
                if "type" in entry:
                    entry_type = entry["type"]
                    if " *" not in entry_type:
                        entry_type = entry_type.replace("*", " *")

                name_core = name
                if "[" in name:
                    name_core = name[:name.find("[")]

                # if we want to initialize member (subitem) then we need to swap entity entry with subitem entry
                if is_subitem:
                    if not is_hidden:
                        entry, name_core = self.find_subitem(name, item)
                    else:
                        entry, name_core = self.find_hidden_subitem(name, item)

                if is_subitem or name_core in entry["name"] or entry_type == self.codegen._get_typename_from_type(type):
                    if self.args.debug_vars_init:
                        logging.info(
                            f"In {entity_name} we detected that item {name} of type {entry_type} has a user-specified init")

                    if "nullterminated" in entry:
                        if entry["nullterminated"] == "True":
                            null_terminate = True

                    if "tagged" in entry:
                        if entry["tagged"] == "True":
                            tag = True

                    if "value" in entry:
                        value = entry["value"]

                    if "value_dep" in entry:
                        rely_vals = entry["value_dep"][:]
                        for i in rely_vals:
                            if i[0] in ["-", "."]:
                                value_dep += name_core + i
                            else:
                                value_dep += i

                    if "min_value" in entry:
                        min_value = entry["min_value"]

                    if "max_value" in entry:
                        max_value = entry["max_value"]

                    if "user_name" in entry and not is_subitem:
                        if name == name_core:
                            name = entry["user_name"]
                        else:
                            name = entry["user_name"] + name[name.find('['):]

                    if "size" in entry:
                        loop_count = entry["size"]
                        if "size_dep" in entry:
                            # check if the dependent param is present (for functions only)
                            dep_id = entry["size_dep"]["id"]
                            dep_add = entry["size_dep"]["add"]
                            dep_names = []
                            dep_user_name = ""
                            dep_found = False
                            iterate = None
                            if not is_subitem:
                                iterate = item["items"]
                            else:
                                index_tmp = name.rfind("-")
                                name_tmp = name[:index_tmp]
                                entry_tmp, name_core_tmp = self.find_subitem(name_tmp, item)
                                iterate = entry_tmp["subitems"]
                            
                            for i in iterate:
                                if i["id"] == dep_id:
                                    dep_names = i["name"]
                                    if "user_name" in i:
                                        if not is_subitem:
                                            dep_user_name = i["user_name"]
                                        else:
                                            index_tmp = name.rfind("-")
                                            name_core_tmp = name[:index_tmp]
                                            dep_user_name = name_core_tmp + "->" + i["user_name"]
                                    else:
                                        logging.error(
                                            "user_name not in data spec and size_dep used")
                                        sys.exit(1)
                                    dep_found = True
                                    break

                            if dep_found and is_subitem:
                                loop_count = dep_user_name
                                if dep_add != 0:
                                    loop_count = f"{loop_count} + {dep_add}"
                            elif dep_found and fid:
                                f = self.dbops.fnidmap[fid]
                                if f is not None and len(dep_names) > 0:
                                    parms = []
                                    for l in f["locals"]:
                                        if l["parm"]:
                                            parms.append(l)
                                    parms.sort(key=lambda k: k['id'])
                                    for p in parms:
                                        if "name" in p:
                                            param_name = p["name"]
                                            if param_name in dep_names:
                                                loop_count = dep_user_name
                                                if dep_add != 0:
                                                    loop_count = f"{loop_count} + {dep_add}"

                    if "pointer" in entry:
                        if entry["pointer"] == "True":
                            isPointer = True

                    if "protected" in entry and entry["protected"] == "True":
                        protected = True

                    if "fuzz" in entry:
                        if entry["fuzz"] == "True":
                            fuzz = 1
                        else:
                            fuzz = 0

                    if "fuzz_offset" in entry:
                        fuzz_offset = entry["fuzz_offset"]

                    if "subitems" in entry:
                        subitems_names = []
                        for u in entry["subitems"]:
                            if len(u["name"]) == 0:
                                if hidden_members == None:
                                    hidden_members = []
                                hidden_members.append(u["id"])
                            else:
                                subitems_names.append(u["name"][0]) # if it's subitem then there is only one name

                    if "always_init" in entry:
                        always_init = entry["always_init"]

                    if "force_type" in entry:
                        cast_str = entry["force_type"]

                    user_init = True
                    break  # no need to look further

        return loop_count, null_terminate, tag, value, min_value, max_value, protected, value_dep, isPointer, fuzz_offset, user_init, fuzz, is_hidden, \
            is_subitem, name, typename, subitems_names, hidden_members, always_init, cast_str

    # -------------------------------------------------------------------------
    
    # Given variable name and type, generate correct variable initialization code.
    # For example:
    # name = var, type = struct A*
    # code: struct A* var = (struct A*)malloc(sizeof(struct A*));
    # @belongs: init
    def _generate_var_init(self, name, type, pointers, level=0, skip_init=False, known_type_names=None, cast_str=None, new_types=None,
                           entity_name=None, init_obj=None, fuse=None, fid=None, count=None, data=None, is_subitem=False, subitems_names=None, hidden_members=None,
                           is_hidden=False, always_init=None):
        """Given variable name and type, generate correct variable initialization code.
        For example:
        name = var, type = struct A*
        code: struct A* var = (struct A*)malloc(sizeof(struct A*));
     
        Notes:
        The callers of this function are (in this order):
        _generate_function_call: for initialization of parameters
        generate_off_target: for initialization of globals
        _generate_var_init: recursive calls
        
        :param name: the name of the initialized entity (i.e. a variable, field, global); it can be a fresh entity, e.g.
                    a new variable introduced for purposes of initialization of arrays; constant in recursive calls
        :param type: the recorded type of the name entity (i.e. the corresponding entry in types db); constant in 
                    recursive calls
        :param pointers: a list consisting of all the pointers that have been successfully initialized in a call 
                    of this function; not used anywhere apart from recursive calls, always empty at the top call
        :param level: the level of nesting brackets when initializing arrays; defaults to 0, always 0 at the top call,
                    increased when what is in arrays also needs recursive initialization
        :param skip_init: a flag that when set true prevents initialization of further pointers; defaults to False,
                    always False at the top call
        :param known_type_names: names of all the record types found in the source tree of the OT, defaults to None
        :param cast_str: at certain moments it is the type of the initialized entity used in such expressions as
                         ((type)base)->field, defaults to None
        :param new_types: type ids for the entities found during initialization, defaults to None
        :param entity_name: the name of the wrapping function, only used for top-level analyses - for instance if x is 
                            dealt with in f(void* x) then entity_name is 'f' and name is 'x', defaults to None
        :param init_obj: TODO: unknown, defaults to None
        :param fuse: recursion depth; if None then no limit; defaults to None
        :param fid: the id of the root function of smart init; defaults to None
        :param count: TODO: unknown, defaults to None
        :param data: a dict containing the resolved initialization data for the given variable
        :param is_subitem: a flag that when set true means that variable is a member of struct and appears in init_file,
                             defaults to False
        :param subitems_names: names of members of struct - needed for manipulating initialization order
        :param hidden_members: ids of unnamed payloads that the struct have and that we need to fuzz
        :param is_hidden: a flag that when set true means that it is unnamed payload in struct

        :return: (str, alloc, brk) where str is the verbatim C init code string, alloc is a boolean that says if
                any memory was allocated for the current entity (NOTE: remove, as it is only changed within recursive
                calls, but not read anywhere?), brk is a boolean that is True iff maximal recursion depth was reached
                and is used to break out of the recursion loop
        """
        if entity_name is None:
            entity_name = name
        # in case of typedefs we need to get the first non-typedef type as a point of
        # reference

        if fuse is not None:
            fuse += 1
            if fuse > Init.MAX_RECURSION_DEPTH:
                logging.error("Max recursion depth reached")
                with open(self.args.output_dir + "/aot_recursion_error.txt", "w") as file:
                    file.write(
                        f"Max recursion depth reached while generating var init\n")
                if self.args.ignore_recursion_errors:
                    return "// Recursion loop ignored on an attempt to initialize this variable. Manual init required.\n", False, True 
                else:
                    raise Exception("Breaking execution due to error")

        if False == self.args.init:
            return "", False, False

        base_type = type
    
        if not is_hidden:
            type = self.dbops._get_typedef_dst(type)
            cl = type["class"]
        else:
            cl = "payload"

        if cast_str != None and "struct" in cast_str and subitems_names != None:
            typename = cast_str.replace("*", "", 1)
            typename = typename.strip()
            type = self.find_type_by_name(typename)
            if type == None:
                logging.error("type of given typename not found and force_type used")
                sys.exit(1)
            cl = type["class"]

        if self.args.debug_vars_init and not is_hidden:
            logging.info(
                f"generating var init for {name} cl {cl} type {type['id']}")
            
        if not is_hidden:
            t_id = type["id"]

            if t_id in self.used_types_data:
                type = self.used_types_data[t_id]
                if self.args.debug_vars_init:
                    logging.info(
                        f"used type found for {t_id}. Type id is {type['id']}")
        str = ""

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
        stop_recurrence = False

        dst_type = type

        if not is_hidden:
            typename = self.codegen._get_typename_from_type(type)
        else:
            typename = None

        if not is_hidden and init_obj is not None and init_obj.t_id != dst_type["id"] and type["class"] == "record_forward":
            # see if we might be dealing with record_forward of the same record
            _tmp_id = init_obj.t_id
            _dst_tid = dst_type['id']
            if init_obj.is_pointer:
                _tmp_id = self.dbops._get_real_type(_tmp_id)
                _dst_tid = self.dbops._get_real_type(_dst_tid)
            init_type = self.dbops.typemap[_tmp_id]
            _dst_type = self.dbops.typemap[_dst_tid]
            if init_type["class"] == "record" and _dst_type["class"] == "record_forward" and init_type["str"] == _dst_type["str"]:
                if self.args.debug_vars_init:
                    logging.info(
                        f"Updating dst_type from record_fwd {dst_type['id']} to record {init_obj.t_id}")
                type = self.dbops.typemap[init_obj.t_id]
                dst_type = type
                cl = type["class"]
                t_id = type["id"]

        if "pointer" == cl or "const_array" == cl or "incomplete_array" == cl:

            # let's find out the last component of the name
            index, name_base, member_name, is_arrow = self.get_names_after_extraction(name, backwards=True)
            pointer = is_arrow
            if index == -1:
                member_name = name
                name_base = ""

            if "const_array" == cl:
                dst_type = type["refs"][0]
                dst_size = self.dbops.typemap[dst_type]["size"] // 8
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
                    if self.args.debug_vars_init:
                        logging.warning(
                            "special case: adding a single member to a const array")
                    loop_count = 1  # this is a special corner case -> we already allocated memory for 1 member
                    str += "// increasing the loop count to 1 for a const array of size 0\n"
            elif "incomplete_array" == cl and type['size'] == 0:
                is_array = True
                loop_count = 0
                if self.args.debug_vars_init:
                    logging.warning(
                        "special case: adding a single member to a const array")
                loop_count = 1  # this is a special corner case -> we already allocated memory for 1 member
                str += "// increasing the loop count to 1 for a const array of size 0\n"
            else:
                dst_type = self.dbops._get_typedef_dst(
                    self.dbops.typemap[type["refs"][0]])
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

                        if stub_name not in self.stub_names:
                            self.stub_names.add(stub_name)
                        else:
                            suffix=1
                            while f"{stub_name}_{suffix}" in self.stub_names:
                                suffix += 1
                            stub_name = f"{stub_name}_{suffix}"
                            self.stub_names.add(stub_name)

                        tmp_str, fname = self.codegen._generate_function_stub(dst_type["id"], stubs_file=False,
                                                                              fpointer_stub=True, stub_name=stub_name)

                        str = f"aot_memory_init_func_ptr(&{name}, {fname});\n"
                        data['class'] = Init.INIT_CL_FPTR
                        data['name'] = name
                        data['fid'] = dst_type['id']
                        data['name_raw'] = f"&{name}"
                        data['dst_func'] = fname

                        # str = f"{name} = {fname};\n"
                        if tmp_str not in self.fpointer_stubs:
                            self.fpointer_stubs.append(tmp_str)
                        return str, alloc, False
                    elif (dst_type["id"] in pointers and (pointers.count(dst_type["id"]) > 1 or member_name in ["prev", "next"]) or
                            (member_name in ["pprev"] and self.dbops._get_real_type(dst_type["id"]) in pointers)):
                        # we have already initialized the structure the pointer points to
                        # so we have to break the loop
                        if self.args.debug_vars_init:
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

                        return str, alloc, False
                    elif known_type_names is not None and dst_type["class"] == "record_forward" and dst_type["str"] not in known_type_names:
                        recfwd_found = False
                        if init_obj is not None and init_obj.t_id != dst_type["id"]:
                            # see if we might be dealing with record_forward of the same record
                            _tmp_id = init_obj.t_id
                            if init_obj.is_pointer:
                                _tmp_id = self.dbops._get_real_type(_tmp_id)
                            init_type = self.dbops.typemap[_tmp_id]
                            if init_type["class"] == "record" and dst_type["class"] == "record_forward" and init_type["str"] == dst_type["str"]:
                                if self.args.debug_vars_init:
                                    logging.info(
                                        f"Detected that we are dealing with a pointer to record forward but we know the real record")
                                recfwd_found = True
                        if not recfwd_found:
                            str += f"/*{name} left uninitialized as it's not used */\n"
                            if self.args.debug_vars_init:
                                logging.info(
                                    f"/*{name} left uninitialized as it's not used */\n")
                            return str, False, False

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

                version = False
                null_terminate = False
                tag = False
                value = None
                min_value = None
                max_value = None
                protected = False
                value_dep = "" # Does the value of member is set explicitly by other members' values?
                isPointer = False
                fuzz_offset = None # If it is unnamed payload, we need offset to know where to fuzz
                user_init = False
                fuzz = None
                
                loop_count, null_terminate, tag, value, min_value, max_value, protected, value_dep, isPointer, fuzz_offset, user_init, fuzz, is_hidden, \
                is_subitem, name, typename, subitems_names, hidden_members, always_init, cast_str \
                    = self.read_user_init_data(loop_count, null_terminate, tag, value, min_value, max_value, protected, value_dep, isPointer, \
                                               fuzz_offset, user_init, fuzz, is_hidden, version, entity_name, is_subitem, level, fid, type, name, typename, \
                                                subitems_names, hidden_members, always_init, cast_str)

                if user_init:
                    entry = None
                    single_init = False
                else:
                    entry, single_init, offset_types = self._get_cast_ptr_data(
                        type)
                    if self.args.debug_vars_init:
                        logging.info(
                            f"it's a pointer init obj {init_obj} offset types {offset_types} type {type['id']}")

                    final_objs = []
                    if offset_types is not None and init_obj is not None:
                        if self.args.debug_vars_init:
                            logging.info(f"init_obj is {init_obj}")
                        to_process = []
                        to_keep = []
                        if self.args.debug_vars_init:
                            logging.info(
                                f"this init_obj has {len(init_obj.offsetof_types)} offsetof_types")
                        for types, members, obj in init_obj.offsetof_types:
                            to_keep = []  # indices to remove
                            for i in range(len(offset_types)):
                                _types, _members = offset_types[i]
                                if _types == types and _members == members:
                                    to_keep.append(i)
                                    to_process.append((types, members, obj))
                                    break
                        tmp = []
                        if len(to_keep) < len(offset_types):
                            if self.args.debug_vars_init:
                                logging.info(
                                    f"We reduced offset_types by using derefs trace info")
                                logging.info(
                                    f"Before it was {len(offset_types)} now it is {len(to_keep)}")
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
                                if self.args.debug_vars_init:
                                    logging.info(
                                        "No more offset types, the object is final")
                            else:
                                for _types, _members, _obj in obj.offsetof_types:
                                    to_process.append((_types, _members, _obj))
                        if len(final) > 0:
                            if self.args.debug_vars_init:
                                logging.info("updating offset types")
                            offset_types = final

                    if offset_types is not None and (0 == len(offset_types)):
                        offset_types = None

                if not user_init and offset_types is not None:  # and level == 0
                    str_tmp = ""
                    # this type has been used to pull in its containing type
                    str_tmp += "\n// smart init : we detected that the type is used in the offsetof operator"

                    # we will have to emit a fresh variable for the containing type
                    variant = ""
                    variant_num = 1
                    i = 0
                    for i in range(len(offset_types)):

                        types, members = offset_types[i]
                        # the destination type of offsetof goes first
                        _dst_t = self.dbops.typemap[types[0]]
                        typename = self.codegen._get_typename_from_type(_dst_t)
                        _dst_tid = _dst_t["id"]
                        if new_types is not None:
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
                            last_type = self.dbops.typemap[last_tid]
                            if last_type["class"] == "const_array" or (last_type["class"] == "incomplete_array" and last_type["size"] == 0):
                                array_count = self._get_const_array_size(
                                    last_type)
                                if 0 == array_count:
                                    # a special case of variable lenght array as the last member of a struct
                                    is_vla_struct = True
                                    last_type_name = self.codegen._get_typename_from_type(
                                        last_type).replace("[0]", "").replace("*", "", 1) # if it's a pointer, we allocate space for the dst type
                                    extra_padding = f"sizeof({last_type_name})"

                        if not is_vla_struct:
                            str_tmp += f"\n{typename} {fresh_var_name};"
                        else:
                            str_tmp += f"\n// making extra space for the variable lenght array at the end of the struct"
                            str_tmp += f"\n{typename}* {fresh_var_name};"
                            str_tmp += f"\naot_memory_init_ptr((void**) &{fresh_var_name}, sizeof({typename}) + {extra_padding}, 1 /* count */, 0 /* fuzz */, \"\");"
                            fresh_var_name = f"(*{fresh_var_name})"
                            data['tid'] = _dst_tid
                            data['name'] = name
                            data['size'] = f"sizeof({typename}) + {extra_padding}"
                            data['count'] = 1
                            data['fuzz'] = 0
                            data['class'] = Init.INIT_CL_OFFSETOF

                        if self.args.debug_vars_init:
                            logging.info(
                                f"typename is {typename} name_tmp is {name_tmp} fresh_var_name is {fresh_var_name}")
                        comment = ""
                        if len(offset_types) > 1:
                            comment = "//"
                            variant = f"variant {variant_num}"
                            variant_num += 1
                        str_tmp += "\n{} // smart init {}\n".format(
                            comment, variant)
                        # str += "{} aot_memory_init_ptr(&{}, sizeof({}), {} /* count */, {} /* fuzz */);\n".format(
                        #     comment, name, typename, self.ptr_init_size, fuzz)
                        # pointers.append(dst_t["id"])

                        obj = None
                        if i < len(final_objs):
                            obj = final_objs[i]
                        elif init_obj is not None:
                            if self.args.debug_vars_init:
                                logging.info(
                                    f"not enough objects in final_objs: len is {len(final_objs)}, init_obj: {init_obj} ")
                            raise Exception("Breaking execution due to error")
                        if obj == init_obj:
                            if self.args.debug_vars_init:
                                logging.info(f"Object is the same {obj}")
                            # sys.exit(1)
                        else:
                            if self.args.debug_vars_init:
                                logging.info(
                                    f"Object is different obj is {obj}")

                        # we have to assign our top-level
                        # parameter to the right member of the containing type
                        member_name = ""
                        member_number = -1                        
                        member_tid = None
                        for i in range(len(members)):
                            member_no = members[i]
                            _tmp_t = self.dbops.typemap[types[i]]
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
                            member_number = member_no
                            member_tid = _tmp_t['refs'][member_no]
                        str_tmp += f"{name} = &{fresh_var_name}.{member_name};\n"
                        data['offset_member'] = member_name
                        data['offset_member_num'] = member_number

                        if self.args.debug_vars_init:
                            logging.info("variant c")
                        brk = False
                        if len(offset_types) > 1 and variant_num > 2 and self.args.single_init_only:
                            str_tmp = ""
                        else:
                            # enforce the init of the "anchor" member for the offsetof operator
                            # if obj.t_id in obj.used_members:
                            #     # case1: we try to match the existing TypeUse object and use it to mark
                            #     # that the "anchor" member is used -> this is a prefeable solution
                            #     if member_number not in obj.used_members[obj.t_id]:
                            #         obj.used_members[obj.t_id][member_number] = {}
                            #     o_found = False
                            #     for o in self.typeuse_obj_db:
                            #         o_found = False
                            #         if o.t_id == member_tid or (o.is_pointer and self.dbops._get_real_type(o.t_id) == member_tid):
                            #             for _types, _members, _obj in o.offsetof_types:
                            #                 for index in range(len(_types)):
                            #                     if _obj.id == obj.id and _members[index] == member_number: 
                            #                         obj.used_members[obj.t_id][member_number] = o
                            #                         o_found = True
                            #                         break
                            #                 if o_found is True:
                            #                     break
                            #             if o_found is True:
                            #                 break 
                                    
                            #     if o_found and -1 == self.used_types_data[obj.t_id]['usedrefs'][member_number]:
                            #         self.used_types_data[obj.t_id]['usedrefs'][member_number] = self.used_types_data[obj.t_id]['refs'][member_number]
                            # else:
                            # case2: we add the member usage info to an entire type of the member
                            # this works but at the disadvantage of having to initialize all instances 
                            # whenever the member is used 
                            if _dst_t['id'] not in self.used_types_data:
                                self.used_types_data[_dst_t['id']] = _dst_t
                            self.used_types_data[_dst_t['id']]['usedrefs'][member_number] = self.used_types_data[_dst_t['id']]['refs'][member_number] 
                            if 'offsetof' not in data:
                                data['offsetof'] = {}
                            _str_tmp, alloc_tmp, brk = self._generate_var_init(fresh_var_name,
                                                                            _dst_t,
                                                                            pointers[:],
                                                                            level,
                                                                            skip_init,
                                                                            known_type_names=known_type_names,
                                                                            cast_str=None,
                                                                            new_types=new_types,
                                                                            init_obj=obj,
                                                                            fuse=fuse,
                                                                            data=data['offsetof'])
                            str_tmp += _str_tmp
                        i += 1

                        if len(offset_types) > 1 and variant_num > 2:
                            str_tmp = str_tmp.replace("\n", "\n//")
                            if str_tmp.endswith("//"):
                                str_tmp = str_tmp[:-2]

                        str += str_tmp
                        alloc = False
                        if brk:
                            return str, False, brk


                    # if len(offset_types) == 1:
                    if self.args.debug_vars_init:
                        logging.info("Returning after detecting offsetof")
                    # logging.info(f"str is {str}, offset_types len is {len(offset_types)}, str_tmp is {str_tmp}")
                    return str, alloc, False
                else:  # todo: consider supporting offsetof + cast at level 0

                    force_ptr_init = False
                    if not user_init and entry is not None and init_obj is not None:
                        if self.args.debug_vars_init:
                            logging.info(
                                f"this is not user init, entry is {entry}")
                        # entry is not None, which means we have some casts
                        # let's check if we have some additional hints in our init object
                        # we keed all casts history in the cast_types array, but the
                        # latest type is always stored in the t_id/original_tid
                        latest_tid = init_obj.original_tid
                        if latest_tid in entry[Init.CAST_PTR_NO_MEMBER]:
                            if self.args.debug_vars_init:
                                logging.info(
                                    f"Current object's tid {latest_tid} detected in entry - will use that one")
                            entry = copy.deepcopy(entry)
                            entry[Init.CAST_PTR_NO_MEMBER] = [latest_tid]
                            single_init = True
                        else:
                            if self.args.debug_vars_init:
                                logging.info(
                                    f"current tid {latest_tid} not found in entry")

                        skipped_count = 0
                        for _tid in entry[Init.CAST_PTR_NO_MEMBER]:
                            active_type = self.dbops.typemap[self.dbops._get_real_type(
                                t_id)]
                            active_type = self.dbops._get_typedef_dst(
                                active_type)
                            casted_type = self.dbops.typemap[self.dbops._get_real_type(
                                _tid)]
                            casted_type = self.dbops._get_typedef_dst(
                                casted_type)
                            struct_types = ["record", "record_forward"]
                            if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                skipped_count += 1

                        if not skip_init and skipped_count == len(entry[Init.CAST_PTR_NO_MEMBER]):
                            # we have to do it since there will be no init in the other case
                            force_ptr_init = True

                    if not single_init or force_ptr_init:
                        typename = typename.replace("*", "", 1)
                        typename = typename.strip()
                        if fuzz is None:
                            fuzz = int(self._to_fuzz_or_not_to_fuzz(dst_type))

                        extra_padding = None
                        # test for a corner case: a struct with the last member being a const array of size 0
                        if dst_type["class"] == "record" and len(dst_type["refs"]) > 0:
                            last_tid = dst_type["refs"][-1]
                            last_type = self.dbops.typemap[last_tid]
                            if last_type["class"] == "const_array" or (last_type["class"] == "incomplete_array" and last_type["size"] == 0):
                                array_count = self._get_const_array_size(
                                    last_type)
                                if 0 == array_count:
                                    # corner case detected -> it means that we have to add allocate some special room
                                    # to accommodate for that
                                    last_type_name = self.codegen._get_typename_from_type(
                                        last_type).replace("[0]", "")
                                    extra_padding = f"sizeof({last_type_name})"
                                    logging.warning(
                                        f"Our current item {name} of type {typename} has a zero-sized array")

                        # check all the types the object was casted to and select the size which
                        # fits the largest of those types
                        multiplier = None

                        names = set()
                        if init_obj is not None and not user_init:
                            if len(init_obj.cast_types) > 0:
                                max = dst_type["size"]
                                for _obj_tid, _obj_orig_tid, _is_ptr in init_obj.cast_types:
                                    final_tid = _obj_orig_tid
                                    if _is_ptr:
                                        final_tid = self.dbops._get_real_type(
                                            final_tid)
                                    final_type = self.dbops.typemap[final_tid]
                                    names.add(
                                        self.codegen._get_typename_from_type(final_type))

                                    final_type = self.dbops._get_typedef_dst(
                                        final_type)
                                    if final_type["size"] > max:
                                        max = final_type["size"]
                                if max > dst_type["size"]:
                                    if dst_type["size"] == 0:
                                        if max % 8 == 0:
                                            multiplier = f"{max // 8}"
                                        else:
                                            multiplier = f"{max // 8} + 1"
                                    else:
                                        multiplier = (
                                            max // dst_type["size"]) + 1
                                        multiplier = f"sizeof({typename})*{multiplier}"
                                    if extra_padding:
                                        multiplier = f"{multiplier} + {extra_padding.replace('*', '', 1)}"
                                        str += f"// smart init: allocating extra space for a 0-size const array member\n"
                                    str += f"// smart init: this object has many casts: using larger count to accommodate the biggest casted type\n"
                                    str += f"// the other types are: {sorted(names)}\n"

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
                                if value_dep == "":
                                    str += f"aot_memory_init_ptr((void**) &{name}, sizeof({typename}), {cnt} /* count */, {fuzz} /* fuzz */, {tagged_var_name});\n"
                                else:
                                    # case: ptr points to the same thing as sth we already allocated!
                                    str += f"\n// this ptr points to the space that we have already allocated\n"
                                    str += f"aot_memory_init(&{name}, sizeof(unsigned long int), {fuzz} /* fuzz */, {tagged_var_name});\n"
                                    str += f"{name} = {value_dep};\n"
                            else:
                                # a rather rare case of extra padding being non-zero
                                str += f"// smart init: allocating extra space for a 0-size const array member\n"
                                str += "aot_memory_init_ptr((void**) &{}, sizeof({}) + {}, {} /* count */, {} /* fuzz */, {});\n".format(
                                    name, typename, extra_padding.replace("*", "", 1), cnt, fuzz, tagged_var_name)
                        else:
                            str += "aot_memory_init_ptr((void**) &{}, {}, {} /* count */, {} /* fuzz */, {});\n".format(
                                name, multiplier, cnt, fuzz, tagged_var_name)
                        data['tid'] = type['id']
                        data['name_raw'] = name
                        data['name'] = f"(void**) &{name}"
                        data['size'] = f"sizeof({typename})"
                        if extra_padding is not None:
                            data['padding'] = extra_padding.replace("*", "", 1)
                        data['count'] = cnt
                        data['class'] = Init.INIT_CL_PTR
                        data['fuzz'] = fuzz

                        if addsize and not null_terminate:
                            # use intermediate var to get around const pointers
                            str += f"tmpname = {name};\n"
                            str += f"tmpname[{cnt} - 1] = '\\0';\n"

                        if null_terminate:
                            str += f"{name}[{loop_count} - 1] = 0;\n"

                        if value is not None:
                            str += f"#ifdef KLEE\n"
                            str += "if (AOT_argc == 1) {\n"
                            str += f"    klee_assume(*{name} == {value});\n"
                            str += "}\n"
                            str += f"#endif\n"
                            data['value'] = value
                        if min_value is not None:
                            str += f"if (*{name} < {min_value}) *{name} = {min_value};\n"
                            data['min_value'] = min_value
                        if max_value is not None:
                            str += f"if (*{name} > {max_value}) *{name} = {max_value};\n"
                            data['max_value'] = max_value
                        if tag:
                            str += f"aot_tag_memory({name}, sizeof({typename}) * {cnt}, 0);\n"
                            str += f"aot_tag_memory(&{name}, sizeof({name}), 0);\n"
                        data['tag'] = tag
                        data['tag_name'] = tagged_var_name

                        if protected:
                            str += f"aot_protect_ptr(&{name});\n"
                            stop_recurrence = True
                        data['protected'] = protected

                    if not skip_init and entry is not None:
                        # we are dealing with a pointer for which we have found a cast in the code

                        variant = ""
                        variant_num = 1
                        cast_done = False
                        for _dst_tid in entry[Init.CAST_PTR_NO_MEMBER]:
                            _dst_t = self.dbops.typemap[_dst_tid]
                            typename = self.codegen._get_typename_from_type(
                                _dst_t)

                            active_type = self.dbops.typemap[self.dbops._get_real_type(
                                t_id)]
                            active_type = self.dbops._get_typedef_dst(
                                active_type)
                            casted_type = self.dbops.typemap[self.dbops._get_real_type(
                                _dst_tid)]
                            casted_type = self.dbops._get_typedef_dst(
                                casted_type)
                            struct_types = ["record", "record_forward"]
                            if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                if self.args.debug_vars_init:
                                    logging.info(
                                        "will not consider cast of structural type to non-structural type")
                                continue

                            if new_types is not None:
                                new_types.add(_dst_tid)
                            fuzz = int(self._to_fuzz_or_not_to_fuzz(_dst_t))

                            comment = ""
                            # str += "{} aot_memory_init_ptr(&{}, sizeof({}), {} /* count */, {} /* fuzz */);\n".format(
                            #     comment, name, typename, self.ptr_init_size, fuzz)
                            # pointers.append(dst_t["id"])
                            if self.args.debug_vars_init:
                                logging.info("variant d")
                            cast_done = True
                            brk = False
                            if not single_init and self.args.single_init_only:
                                str_tmp = ""
                            else:
                                str_tmp, alloc_tmp, brk = self._generate_var_init(name,
                                                                                _dst_t,
                                                                                pointers[:],
                                                                                level,
                                                                                skip_init,
                                                                                known_type_names=known_type_names,
                                                                                cast_str=typename,
                                                                                new_types=new_types,
                                                                                init_obj=init_obj,
                                                                                fuse=fuse,
                                                                                data=data)
                                if not single_init:
                                    comment = "//"
                                    variant = f"variant {variant_num}"
                                    variant_num += 1
                                str_tmp = "\n{} // smart init (a) {}: we've found that this pointer var is casted to another type: {}\n{}".format(
                                    comment, variant, typename, str_tmp)
                            # logging.info(str_tmp)
                            if not single_init:
                                str_tmp = str_tmp.replace(
                                    "\n", "\n//")
                                if str_tmp.endswith("//"):
                                    str_tmp = str_tmp[:-2]
                            str += str_tmp
                            if brk:
                                return str, False, brk

                        # len(entry[Generator.CAST_PTR_NO_MEMBER]) == 1 and cast_done == True:
                        if cast_done == True:
                            if self.args.debug_vars_init:
                                logging.info(
                                    "Returning after detecting a cast")
                            return str, alloc, False
                    alloc = True
        else:
            if (level == 0 and skip_init == False) or cl in ["builtin", "enum", "payload"]:

                loop_count = 1
                version = True
                null_terminate = False
                tag = False
                value = None
                min_value = None
                max_value = None
                protected = False
                value_dep = "" # Does the value of member is set explicitly by other members' values?
                isPointer = False
                fuzz_offset = None # If it is unnamed payload, we need offset to know where to fuzz
                user_init = False
                fuzz = None

                loop_count, null_terminate, tag, value, min_value, max_value, protected, value_dep, isPointer, fuzz_offset, user_init, fuzz, is_hidden, \
                is_subitem, name, typename, subitems_names, hidden_members, always_init, cast_str \
                    = self.read_user_init_data(loop_count, null_terminate, tag, value, min_value, max_value, protected, value_dep, isPointer, \
                                               fuzz_offset, user_init, fuzz, is_hidden, version, entity_name, is_subitem, level, fid, type, name, typename, \
                                                subitems_names, hidden_members, always_init, cast_str)

                tagged_var_name = 0
                if tag:
                    tagged_var_name = self._get_tagged_var_name()
                if not isPointer:
                    if is_hidden or 'c' not in type["qualifiers"] and 'c' not in base_type['qualifiers']:
                        if not is_hidden:
                            str += f"aot_memory_init(&{name}, sizeof({typename}), {fuzz} /* fuzz */, {tagged_var_name});\n"
                            if value_dep != "":
                                str += f"{name} = {value_dep};\n"
                        else:
                            # extract the name without the index of hidden member at the end
                            index, name_base, name_left, is_arrow = self.get_names_after_extraction(name, backwards=True)
                            str += f"aot_memory_init({name_base} + {fuzz_offset}, {loop_count}, {fuzz} /* fuzz */, {tagged_var_name});\n"
                    else:
                        str += f"// skipping init for {name}, since it's const\n"
                        stop_recurrence = True
                else:
                    # special case: non-pointer value is to be treated as a pointer
                    str += f"{typename}* {name}_ptr;\n"
                    str += f"aot_memory_init_ptr((void**) &{name}_ptr, sizeof({typename}), {loop_count}, 1 /* fuzz */, {tagged_var_name});\n"
                if not is_hidden:
                    data['tid'] = type['id']
                data['size'] = f"sizeof({typename})"
                data['name_raw'] = name
                if not isPointer:
                    data['count'] = 1
                else:
                    data['count'] = loop_count
                if not isPointer:
                    data['name'] = f"&{name}"
                    data['class'] = Init.INIT_CL_NONPTR
                    data['fuzz'] = 0
                else:
                    data['name'] = f"(void**) &{name}_ptr"
                    data['class'] = Init.INIT_CL_PTR
                    data['fuzz'] = 1

                if value is not None:
                    str += "#ifdef KLEE\n"
                    str += "if (AOT_argc == 1) {\n"
                    if not isPointer:
                        str += f"    klee_assume({name} == {value});\n"
                    else:
                        str += f"    klee_assume(*{name} == {value});\n"
                    str += "}\n"
                    str += "#endif\n"
                    data['value'] = value

                if isPointer is False:
                    deref = ""
                else:
                    deref = "*"
                if min_value is not None:
                    str += f"if ({deref}{name} < {min_value}) {deref}{name} = {min_value};\n"
                    data['min_value'] = min_value
                if max_value is not None:
                    str += f"if ({deref}{name} > {max_value}) {deref}{name} = {max_value};\n"
                    data['max_value'] = max_value
                if tag:
                    if not isPointer:
                        if not is_hidden:
                            str += f"aot_tag_memory(&{name}, sizeof({typename}), 0);\n"
                        else:
                            index = name.rfind("-")
                            name_tmp = name[:index]
                            str += f"aot_tag_memory({name_tmp} + {fuzz_offset}, {loop_count}, 0);\n"
                    else:
                        str += f"aot_tag_memory({name}_ptr, sizeof({typename}) * {loop_count}, 0);\n"
                        str += f"aot_tag_memory(&{name}_ptr, sizeof({name}_ptr), 0);\n"
                data['tag'] = tag
                data['tag_name'] = tagged_var_name

                if protected and isPointer:
                    str += f"aot_protect_ptr(&{name}_ptr);\n"
                    stop_recurrence = True
                data['protected'] = protected

                if isPointer:
                    str += f"{name} = ({typename}){name}_ptr;\n"

        if cl == "record" and t_id not in self.used_types_data and level > 1:
            typename = self.codegen._get_typename_from_type(
                self.dbops.typemap[t_id])
            return f"// {name} of type {typename} is not used anywhere\n", False, False

        # now that we have initialized the top-level object we need to make sure that
        # all potential pointers inside are initialized too
        # TBD
        # things to consider: pointer fields in structs, members of arrays
        # it seems we need to recursively initialize everything that is not a built-in type
        go_deeper = False
        for_loop = False
        if cl not in ["builtin", "enum", "payload"]:
            # first, let's check if any of the refs in the type is non-builtin
            refs = []
            if self.args.used_types_only and cl == "record":
                refs = type["usedrefs"]
            else:
                refs = type["refs"]

            for t_id in refs:
                tmp_t = self.dbops.typemap[t_id]
                if tmp_t:
                    tmp_t = self.dbops._get_typedef_dst(tmp_t)
                    if tmp_t["class"] != "builtin" and tmp_t["class"] != "enum":
                        go_deeper = True
                        break

            if subitems_names != None:
                go_deeper = True

            if go_deeper == False:
                if "usedrefs" in type and cl != "pointer" and cl != "enum":
                    for u in type["usedrefs"]:
                        if u != -1:
                            go_deeper = True
                            break
            
            if go_deeper and not stop_recurrence:
                alloc_tmp = False
                if is_array:
                    # in case of arrays we have to initialize each member separately
                    index = f"i_{level}"
                    # assuming an array has only one ref
                    member_type = type["refs"][0]
                    member_type = self.dbops.typemap[member_type]
                    for_loop = (
                        (count is None and (not isinstance(loop_count, int) or loop_count > 1))
                        or cl == "const_array"
                        or cl == "incomplete_array"
                    )
                    final_cl = self.dbops._get_typedef_dst(member_type)['class']
                    if for_loop is True and final_cl == "builtin":
                        # in case we have an array of builtins, there is no need to initialize them
                        # one by one in a loop; instead we should initialize the entire array 
                        str_tmp = f"aot_memory_init({name}, sizeof({member_type['str']}) * {loop_count} /* count */, 1 /* fuzz */, 0);\n"
                        data['loop_count'] = loop_count
                        str += str_tmp
                        return str, False, False

                    if for_loop:
                        # please note that the loop_count could only be > 0 for an incomplete array if it
                        # was artificially increased in AoT; normally the size of such array in db.json would be 0
                        str += f"for (int {index} = 0; {index} < {loop_count}; {index}++) ""{\n"
                        if cast_str is not None and "[" in cast_str:
                            cast_str = cast_str[:cast_str.find('[')]
                    skip = False
                    if member_type["class"] == "const_array":
                        # const arrays are initialized with enough space already;
                        # we need to pass that information in the recursive call so that
                        # redundant allocations are not made
                        skip = True
                    if cl == "pointer":
                        skip = True

                    tmp_name = ""
                    if for_loop:
                        tmp_name = f"{name}[{index}]"
                    else:
                        tmp_name = name
                    if name_change:
                        tmp_name = f"(*{tmp_name})"
                    if self.args.debug_vars_init:
                        logging.info(
                            f"variant E, my type is {type['id']}, loop_count is {loop_count}, cl is {cl}: {tmp_name}")

                    str_tmp, alloc_tmp, brk = self._generate_var_init(f"{tmp_name}",
                                                                      member_type,
                                                                      pointers[:],
                                                                      level + 1,
                                                                      skip,
                                                                      known_type_names=known_type_names,
                                                                      cast_str=cast_str,
                                                                      new_types=new_types,
                                                                      entity_name=(entity_name if subitems_names != None else None),
                                                                      init_obj=init_obj,
                                                                      fuse=fuse,
                                                                      data=data,
                                                                      subitems_names=subitems_names,
                                                                      hidden_members=hidden_members,
                                                                      always_init=always_init)
                    if for_loop:
                        data['loop_count'] = loop_count
                    
                    str += str_tmp
                    if brk:
                        return str, False, brk

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
                        if _t_id in self.deps.dup_types:
                            dups = [
                                d for d in self.deps.dup_types[_t_id] if d != _t_id]
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
                            data['bitfields'] = []
                            data['tid'] = _t_id
                            data['fuzz'] = 1

                        for i, bitcount in bitfields.items():
                            field_name = type["refnames"][i]
                            tmp_tid = type["refs"][i]
                            tmp_t = self.dbops._get_typedef_dst(
                                self.dbops.typemap[tmp_tid])
                            # we can generate bitfield init straight away as bitfields are integral types, therefore builtin
                            str_tmp += f".{field_name} = aot_memory_init_bitfield({bitcount}, 1 /* fuzz */, 0), "
                            data['bitfields'].append({"name": field_name, "bitcount": bitcount})

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

                        members_order, size_constraints = self._get_members_order(type, subitems_names)

                        member_to_name = {}
                        for i in members_order:

                            field_name = type["refnames"][i]

                            # is_typedecl = False
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

                            if is_in_use or (always_init != None and field_name in always_init):
                                tmp_tid = type["refs"][i]
                                obj = init_obj
                                if init_obj is not None:
                                    if init_obj.t_id in init_obj.used_members:
                                        if i in init_obj.used_members[init_obj.t_id]:
                                            if self.args.debug_vars_init:
                                                logging.info(
                                                    f"Member use info detected for {init_obj} member {i}")
                                            obj = init_obj.used_members[init_obj.t_id][i]
                                        # else :
                                        #    logging.info(f"Current init object data found, but member {i} not used")
                                        #    continue
                                    else:
                                        if self.args.debug_vars_init:
                                            logging.info(
                                                f"Could not find member {i} use info in obj tid {init_obj.t_id}")
                                        # continue
                                    # note: currently, if we can't find the member in the current object, we fall back
                                    # to the global member data, which might produce unnecessary inits

                                tmp_t = self.dbops._get_typedef_dst(
                                    self.dbops.typemap[tmp_tid])
                                # if tmp_t["class"] != "builtin":

                                # going deeper
                                if "__!anonrecord__" in tmp_name:
                                    tmp_name = tmp_name.replace(
                                        "__!anonrecord__", "")
                                    deref_str = ""

                                if cast_str is not None:
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
                                    if self.args.debug_vars_init:
                                        logging.info(
                                            f"single_init is {single_init}")

                                    if entry is not None:
                                        # passing skip_init as True in order to prevent
                                        # further initialization of void* as we are handling it here
                                        skip = True
                                    if not single_init:
                                        if self.args.debug_vars_init:
                                            logging.info("variant a")
                                        member_to_name[i] = f"{tmp_name}{deref_str}{field_name}"
                                        if 'members' not in data:
                                            data['members'] = {}
                                        data['members'][i] = {}
                                        # note: members are already appened in the init order
                                        # so there is no need to store the ordering as it is with function params

                                        entity_name_core = entity_name
                                        if entity_name is not None and "[" in entity_name:
                                            entity_name_core = entity_name[:entity_name.find("[")]

                                        is_it_subitem = False
                                        if subitems_names != None:
                                            item = self.dbops.init_data[entity_name_core]
                                            entry_tmp, name_core_tmp = self.find_subitem(f"{tmp_name}{deref_str}{field_name}", item)
                                            is_it_subitem = (True if entry_tmp != None else False)

                                        str_tmp, alloc_tmp, brk = self._generate_var_init(f"{tmp_name}{deref_str}{field_name}",
                                                                                     tmp_t,
                                                                                     pointers[:],
                                                                                     level,
                                                                                     skip_init=skip,
                                                                                     known_type_names=known_type_names,
                                                                                     cast_str=cast_str,
                                                                                     new_types=new_types,
                                                                                     entity_name=(entity_name if is_it_subitem else None),
                                                                                     init_obj=obj,
                                                                                     fuse=fuse,
                                                                                     count=count,
                                                                                     data=data['members'][i],
                                                                                     is_subitem=is_it_subitem)
                                        #data['members'] = [ m for m in data['members'] ]
                                        if len(data['members'][i]) == 0:
                                            del data['members'][i]

                                        if size_member_used:
                                            str += "// smart init: using one struct member as a size of another\n"
                                        str += str_tmp
                                        str += self._generate_constraints_check(
                                            f"{tmp_name}{deref_str}{field_name}", size_constraints[i])
                                        if brk:
                                            return str, False,brk

                                    if entry is not None:
                                        if self.args.debug_vars_init:
                                            logging.info("variant b")
                                        variant = ""
                                        variant_num = 1
                                        for dst_tid in entry[i]:
                                            dst_t = self.dbops.typemap[dst_tid]
                                            typename = self.codegen._get_typename_from_type(
                                                dst_t)

                                            active_type = self.dbops.typemap[self.dbops._get_real_type(
                                                tmp_tid)]
                                            active_type = self.dbops._get_typedef_dst(
                                                active_type)
                                            casted_type = self.dbops.typemap[self.dbops._get_real_type(
                                                dst_tid)]
                                            casted_type = self.dbops._get_typedef_dst(
                                                casted_type)
                                            struct_types = [
                                                "record", "record_forward"]
                                            if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                                if self.args.debug_vars_init:
                                                    logging.info(
                                                        "will not consider cast of structural type to non-structural type")
                                                continue

                                            if new_types is not None:
                                                new_types.add(dst_tid)

                                            brk = False
                                            if not single_init and self.args.single_init_only:
                                                str_tmp = ""                                                
                                            else:
                                                # generate an alternative init for each of the detected casts
                                                if 'members' not in data:
                                                    data['members'] = {}
                                                data['members'][i] = {}

                                                entity_name_core = entity_name
                                                if entity_name is not None and "[" in entity_name:
                                                    entity_name_core = entity_name[:entity_name.find("[")]

                                                is_it_subitem = False
                                                if subitems_names != None:
                                                    item = self.dbops.init_data[entity_name_core]
                                                    entry_tmp, name_core_tmp = self.find_subitem(f"{tmp_name}{deref_str}{field_name}", item)
                                                    is_it_subitem = (True if entry_tmp != None else False)

                                                str_tmp, alloc_tmp, brk = self._generate_var_init(f"{tmp_name}{deref_str}{field_name}",
                                                                                            dst_t,
                                                                                            pointers[:],
                                                                                            level,
                                                                                            False,
                                                                                            known_type_names=known_type_names,
                                                                                            cast_str=typename,
                                                                                            new_types=new_types,
                                                                                            entity_name=(entity_name if is_it_subitem else None),
                                                                                            init_obj=obj,
                                                                                            fuse=fuse,
                                                                                            count=count,
                                                                                            data=data['members'][i],
                                                                                            is_subitem=is_it_subitem)
                                                if len(data['members'][i]) == 0:
                                                    del data['members'][i]
                                                if not single_init:
                                                    variant = f"variant {variant_num}"
                                                    variant_num += 1
                                                else:
                                                    member_to_name[i] = f"{tmp_name}{deref_str}{field_name}"
                                                if size_member_used:
                                                    str_tmp = f"// smart init: using one struct member as a size of another\n{str_tmp}"
                                                str_tmp += self._generate_constraints_check(
                                                    f"{tmp_name}{deref_str}{field_name}", size_constraints[i])

                                                str_tmp = f"\n// smart init (b) {variant}: we've found that this pointer var is casted to another type: {typename}\n{str_tmp}"
                                            # logging.info(str_tmp)
                                            if not single_init:
                                                str_tmp = str_tmp.replace(
                                                    "\n", "\n//")
                                                if str_tmp.endswith("//"):
                                                    str_tmp = str_tmp[:-2]
                                            str += str_tmp
                                            if brk:
                                                return str, False, brk
                                            
                        if hidden_members != None:
                            i = len(data['members'])
                            for id in hidden_members:
                                data['members'][i] = {}
                                str_tmp, alloc_tmp, brk = self._generate_var_init(f"{tmp_name}{deref_str}{id}",
                                                                                None,
                                                                                pointers[:],
                                                                                level,
                                                                                False,
                                                                                known_type_names=known_type_names,
                                                                                cast_str=typename,
                                                                                new_types=new_types,
                                                                                entity_name=entity_name,
                                                                                init_obj=obj,
                                                                                fuse=fuse,
                                                                                count=count,
                                                                                data=data['members'][i],
                                                                                is_subitem=True,
                                                                                is_hidden=True)
                                i += 1
                                str += str_tmp
                                if brk:
                                    return str, False, brk

                            # else:
                            #    str += f"// {name}{deref_str}{field_name} never used -> skipping init\n"
                    else:
                        logging.error(
                            f"Unexpected deep var class {cl} for {name}")
                        # sys.exit(1)
            else:
                str += f"// didn't find any deeper use of {name}\n"

        prefix = ""
        if level != 0:
            for i in range(level):
                prefix += "  "
            str = prefix + str
            str = str.replace("\n", f"\n{prefix}")
            str = str[:-(2*level)]

        if for_loop:
            str += f"{prefix}""}\n"  # close the for loop

        return str, alloc, False

    # -------------------------------------------------------------------------

    # @belongs: init
    @staticmethod
    def _sort_order(a, b):
        if a["id"] < b["id"]:
            return -1
        elif a["id"] > b["id"]:
            return 1
        else:
            return 0

    # @belongs: init
    def _collect_derefs_trace(self, f_id, functions):
        # we process functions in DFS mode - starting from f_id and within the scope of the 'functions' set
        # this is supposed to resemble normal sequential execution of a program
        # within each of the functions we need to establish the right order of derefs and function calls
        # since function calls can preceed certain derefs and we operate in a DFS-like way

        DEREF = "deref"
        CALL = "call"

        f = self.dbops.fnidmap[f_id]
        if f is None:
            return []
        self.debug_derefs(f"Collecting derefs for function {f['name']}")
        # first we need to establish a local order of funcs and derefs
        ordered = []
        ord_to_deref = {}
        for d in f["derefs"]:
            ords = []
            if isinstance(d["ord"], list):
                ords = d["ord"]
            else:  # ord is just a number
                ords.append(d["ord"])
            for o in ords:
                ordered.append({"type": DEREF, "id": o, "obj": d})
                derefs_entry = _DerefsEntry(d)
                derefs_entry.init_data(self, f)
                self.derefs_cache[id(d)] = derefs_entry
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
                else:  # ord is just a number
                    ords.append(c["ord"])
                for o in ords:
                    # note: if the deref happens several times in the trace, it will have several entries
                    # in the ord list -> one per each occurrence
                    # below we duplicate the occurrences according to their order in the trace
                    ordered.append({"type": CALL, "id": o, "obj": call_id})
                    self.debug_derefs(f"Appending call {call_id}, ord {o}")
        ordered = sorted(ordered, key=functools.cmp_to_key(Init._sort_order))

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
            deref_id = int(item["id"])  # id is the deref's order -> see above
            cast_data = self.derefs_cache[id(deref)].cast_data
            inserts_num = 0
            if cast_data is not None:
                logging.debug("Cast data is not none")
                for t_id in cast_data:
                    for member in cast_data[t_id]:
                        self.debug_derefs(
                            f"MEMBER IS {member} deref is {deref}")
                        if member != Init.CAST_PTR_NO_MEMBER:
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
                                                    self.debug_derefs(
                                                        f"Moving item {ordered[i]} to index {index} size is {len(ordered)} diff {diff}")
                                                    ordered[i]["id"] -= diff
                                                    ordered.insert(
                                                        index, ordered[i])
                                                    deref_id += 1
                                                    inserts_num += 1
                                                    # and remove the current
                                                    # +1 since we inserted one element before
                                                    del ordered[i + 1]
                                                    # we have to update the ids of items that go after the inserted one
                                                    # for j in range(index + 1, len(ordered)):
                                                    #     ordered[j]["id"] += 1
                                                    self.debug_derefs(
                                                        f"size is {len(ordered)}")
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
            deref_id = int(item["id"])  # id is the deref's order -> see above
            self.debug_derefs(f"processing deref {deref}")

            inserts_num = 0
            if self._get_callref_from_deref(deref):
                self.debug_derefs("callref detected")
                for oref in deref["offsetrefs"]:
                    if oref["kind"] == "callref":
                        # get the related call order
                        ords = f["call_info"][oref["id"]]["ord"]
                        if not isinstance(ords, list):
                            ords = [ords]

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
                                        self.debug_derefs(
                                            f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
                                        ordered[i]["id"] -= diff
                                        ordered.insert(index, ordered[i])
                                        deref_id += 1
                                        inserts_num += 1
                                        del ordered[i + 1]
                                        # we have to update the ids of items that go after the inserted one
                                        # for j in range(index + 1, len(ordered)):
                                        #     ordered[j]["id"] += 1
                                        self.debug_derefs(
                                            f"size is {len(ordered)}")
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
                                            self.debug_derefs(
                                                f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
                                            ordered[i]["id"] -= diff
                                            ordered.insert(index, ordered[i])
                                            deref_id += 1
                                            inserts_num += 1
                                            del ordered[i + 1]
                                            # # we have to update the ids of the items that go after the inserted one
                                            # for j in range(index + 1, len(ordered)):
                                            #     ordered[j]["id"] += 1
                                            self.debug_derefs(
                                                f"size is {len(ordered)}")
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
                                                                            self.debug_derefs(
                                                                                f"Moving member arg {ordered[_i]} from index {_i} to index {index} size is {len(ordered)} diff {diff}")
                                                                            ordered[_i]["id"] -= diff
                                                                            ordered.insert(
                                                                                index, ordered[_i])
                                                                            deref_id += 1
                                                                            inserts_num += 1
                                                                            del ordered[_i + 1]
                                                                            self.debug_derefs(
                                                                                f"size is {len(ordered)}")
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
                                                                                    self.debug_derefs(
                                                                                        f"Moving member arg {ordered[_i]} from index {_i} to index {index} size is {len(ordered)} diff {diff}")
                                                                                    ordered[_i]["id"] -= diff
                                                                                    ordered.insert(
                                                                                        index, ordered[_i])
                                                                                    deref_id += 1
                                                                                    inserts_num += 1
                                                                                    del ordered[_i + 1]
                                                                                    self.debug_derefs(
                                                                                        f"size is {len(ordered)}")

                                if found:
                                    break

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
                                for i in range(len(ordered)):
                                    if ordered[i]["id"] == o:
                                        diff = i - index
                                        self.debug_derefs(
                                            f"Moving item {ordered[i]} from index {i} to index {index} size is {len(ordered)} diff {diff}")
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

        logging.debug(f"ordered trace is {ordered}")

        derefs_trace = []

        for item in ordered:
            if item["type"] == DEREF:
                deref = item["obj"]
                deref_entry = self.derefs_cache[id(deref)]
                if deref_entry.no_data():
                    self.debug_derefs(f"Deref {deref} skipped")
                else:
                    derefs_trace.append((deref_entry, f))
            elif item["type"] == CALL:
                _f_id = item["obj"]
                _functions = set(functions)
                if f_id in _functions:
                    # mark that we processed the current function already
                    _functions.remove(f_id)
                if _f_id in self.trace_cache:
                    derefs_trace.append(self.trace_cache[_f_id])
                else:
                    ftrace = self._collect_derefs_trace(_f_id, _functions)
                    self.trace_cache[_f_id] = ftrace
                    derefs_trace.append(ftrace)

        logging.info(f"Collected trace for function {f['name']}")
        if self.args.debug_derefs:
            for deref_entry, f in _TreeIterator(derefs_trace):
                logging.info(f"{f['id']} : {deref_entry.deref}")

        return derefs_trace

    # -------------------------------------------------------------------------

    # @belongs: init
    def debug_derefs(self, msg):
        if self.args.debug_derefs:
            logging.info(msg)

    # @belongs: init
    def _match_obj_to_type(self, t_id, objects, adjust_recfwd=True):
        self.debug_derefs(f"matching object to type {t_id}")
        matched_objs = []

        for obj in objects:
            if (obj.id, t_id) in self.obj_match_cache:
                if self.obj_match_cache[(obj.id, t_id)]:
                    matched_objs.append(obj)
                continue

            _active_tid = obj.t_id
            _t_id = t_id

            if obj.is_pointer:
                _active_tid = self.dbops._get_real_type(_active_tid)
                _t_id = self.dbops._get_real_type(t_id)

            _active_type = self.dbops.typemap[_active_tid]
            _active_type_recfw = False
            if _active_type["class"] == "record_forward":
                _active_type_recfw = True

            base_type = self.dbops.typemap[_t_id]
            base_type_recfwd = False
            if base_type["class"] == "record_forward":
                base_type_recfwd = True

            obj_matched = False
            if t_id == obj.t_id or _t_id == _active_tid or \
                    (t_id in self.deps.dup_types and obj.t_id in self.deps.dup_types[t_id]) or \
                    (t_id in self.deps.dup_types and _active_tid in self.deps.dup_types[_t_id]) or \
                    ((base_type_recfwd or _active_type_recfw) and (base_type["str"] == _active_type["str"])):
                obj_matched = True
                matched_objs.append(obj)
            # we want to avoid matching void* in historic casts
            elif not self._is_void_ptr(base_type) and base_type["str"] != "void":
                prev_cast_found = False

                for _prev_t_id, _original_tid, _is_pointer in obj.cast_types:
                    self.debug_derefs(
                        f"Checking cast history {_prev_t_id} {_original_tid} {_is_pointer}")
                    if _t_id == _prev_t_id or _t_id == _original_tid or t_id == _prev_t_id or t_id == _original_tid:
                        prev_cast_found = True
                        break
                    _prev_type = self.dbops.typemap[_prev_t_id]
                    _original_type = self.dbops.typemap[_original_tid]
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
                    obj_matched = True
                    matched_objs.append(obj)

            self.obj_match_cache[(obj.id, t_id)] = obj_matched

        if adjust_recfwd and len(matched_objs) == 1:
            # we have exactly one match
            obj = matched_objs[0]
            _t_id = t_id
            _obj_id = obj.t_id
            if obj.is_pointer:
                _t_id = self.dbops._get_real_type(t_id)
                _obj_id = self.dbops._get_real_type(obj.t_id)
            base_type = self.dbops.typemap[_t_id]
            obj_type = self.dbops.typemap[_obj_id]
            if base_type["class"] == "record" and obj_type["class"] == "record_forward":
                # We initially created this object as a record forward type but now
                # we found the corresponding record for it -> let's update the data in the object
                self.debug_derefs(
                    f"Updating object type from record fwd to record {obj.t_id} -> {t_id}")
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
    # @belongs: init
    def _parse_derefs_trace(self, f_id, functions, tids=None):
        # before we can start reasoning we have to collect the trace

        trace = _TreeIterator(self._collect_derefs_trace(f_id, functions))

        # we will now perform an analysis of the collected derefs trace for each of
        # the function parameter types

        # first, let's get the types
        f = self.dbops.fnidmap[f_id]
        arg_tids = f["types"][1:]  # types[0] is a return type of the function
        logging.info(f"Processing derefs for function {f['name']}, trace size is {trace.len()}")
        if tids is not None:
            for t_id in tids:
                arg_tids.append(t_id)

        active_object = None
        typeuse_objects = []
        ret_val = []
        self.typeuse_obj_db = []

        base_obj = None
        for t_id in arg_tids:
            # for a given type we are interested in all casts and offsetof uses
            # what we want to try to learn here is whether the type is used as such or
            # is casted to another type or is a member of another type (offsetof operator)

            # let's create the first TypeUse for the t_id
            base_obj = TypeUse(self.dbops._get_real_type(
                t_id), t_id, self.dbops.typemap[t_id]["class"] == "pointer")
            typeuse_objects = []
            typeuse_objects.append(base_obj)
            base_obj.name = self.codegen._get_typename_from_type(
                self.dbops.typemap[base_obj.t_id])
            logging.info(f"Generated TypeUse {base_obj}")

            active_object = base_obj

            for (deref, cast_data, offsetof_data, member_data, access_order), f in trace:
                self.debug_derefs(f"Deref is {deref}")

                if cast_data is not None:
                    self.debug_derefs(f"cast data is {cast_data}")
                    # current_tid = active_object.t_id
                    for current_tid in cast_data:  # we only check if the current object was casted
                        for member in cast_data[current_tid]:
                            _current_tid = current_tid
                            _active_tid = active_object.t_id
                            if active_object.is_pointer:
                                _current_tid = self.dbops._get_real_type(
                                    _current_tid)

                            if member == Init.CAST_PTR_NO_MEMBER:
                                if current_tid != active_object.t_id and _current_tid != _active_tid:
                                    if current_tid in self.deps.dup_types and active_object.t_id in self.deps.dup_types[current_tid]:
                                        self.debug_derefs("dup")
                                        pass
                                    elif _current_tid in self.deps.dup_types and _active_tid in self.deps.dup_types[_current_tid]:
                                        self.debug_derefs("dup")
                                        pass
                                    else:
                                        other_objs = self._match_obj_to_type(
                                            current_tid, typeuse_objects)
                                        if len(other_objs) == 1:
                                            self.debug_derefs(
                                                f"Active object change detected: from {active_object.id} to {other_objs[0].id}")
                                            active_object = other_objs[0]
                                        else:
                                            self.debug_derefs(
                                                f"Active object id is {active_object.t_id} {_active_tid}, and id is {current_tid} {_current_tid}")
                                            continue
                                # the type is casted directly, i.e. without member dereference
                                casted_tid = cast_data[current_tid][member][0]

                                if active_object.t_id != casted_tid:
                                    active_type = self.dbops.typemap[self.dbops._get_real_type(
                                        active_object.t_id)]
                                    active_type = self.dbops._get_typedef_dst(
                                        active_type)
                                    casted_type = self.dbops.typemap[self.dbops._get_real_type(
                                        casted_tid)]
                                    casted_type = self.dbops._get_typedef_dst(
                                        casted_type)
                                    struct_types = ["record", "record_forward"]
                                    if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                        self.debug_derefs(
                                            "skipping cast of structural type to non-structural type")
                                    else:
                                        self.debug_derefs(
                                            "Adding to casted types")
                                        active_object.cast_types.append(
                                            (active_object.t_id, active_object.original_tid, active_object.is_pointer))
                                        # update the active type of the object
                                        active_object.t_id = casted_tid
                                        active_object.original_tid = casted_tid
                                        if self.dbops.typemap[casted_tid]["class"] == "pointer":
                                            active_object.is_pointer = True
                                        else:
                                            active_object.is_pointer = False
                                        active_object.name = self.codegen._get_typename_from_type(
                                            self.dbops.typemap[active_object.t_id])
                                else:
                                    self.debug_derefs(
                                        "skipping cast due to type mismatch")

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
                                src_type = self.dbops.typemap[current_tid]
                                member_tid = src_type["refs"][member]
                                _member_tid = member_tid
                                if active_object.is_pointer:
                                    _member_tid = self.dbops._get_real_type(
                                        member_tid)

                                if active_object.t_id == member_tid or _active_tid == _member_tid:
                                    casted_tid = cast_data[current_tid][member][0]
                                    active_type = self.dbops.typemap[self.dbops._get_real_type(
                                        active_object.t_id)]
                                    active_type = self.dbops._get_typedef_dst(
                                        active_type)
                                    casted_type = self.dbops.typemap[self.dbops._get_real_type(
                                        casted_tid)]
                                    casted_type = self.dbops._get_typedef_dst(
                                        casted_type)
                                    struct_types = ["record", "record_forward"]
                                    if active_type["class"] in struct_types and casted_type["class"] not in struct_types:
                                        self.debug_derefs(
                                            "skipping cast of structural type to non-structural type")
                                    else:
                                        self.debug_derefs("adding to casts")
                                        active_object.cast_types.append(
                                            (active_object.t_id, active_object.original_tid, active_object.is_pointer))
                                        active_object.t_id = casted_tid
                                        active_object.original_tid = casted_tid
                                        if self.dbops.typemap[casted_tid]["class"] == "pointer":
                                            active_object.is_pointer = True
                                        else:
                                            active_object.is_pointer = False
                                        active_object.name = self.codegen._get_typename_from_type(
                                            self.dbops.typemap[active_object.t_id])
                                else:
                                    self.debug_derefs(
                                        "skipping cast due to type mismatch")
                elif offsetof_data is not None:
                    # first, let's check if we don't have the containing TypeUse object already
                    self.debug_derefs(f"deref is {deref}")

                    member_no = deref["member"][-1]
                    # type[0] is the dst type
                    base_tid = self.dbops.typemap[deref["type"]
                                                  [-1]]["refs"][member_no]
                    dst_tid = deref["type"][0]

                    _base_tid = base_tid
                    _active_tid = active_object.t_id
                    if active_object.is_pointer:
                        _active_tid = self.dbops._get_real_type(
                            _active_tid)

                    if base_tid != active_object.t_id and _base_tid != _active_tid:
                        if base_tid in self.deps.dup_types and active_object.t_id in self.deps.dup_types[base_tid]:
                            self.debug_derefs("dup")
                            pass
                        elif _base_tid in self.deps.dup_types and _active_tid in self.deps.dup_types[_base_tid]:
                            self.debug_derefs("dup")
                            pass
                        else:
                            other_objs = self._match_obj_to_type(
                                base_tid, typeuse_objects)
                            if len(other_objs) == 1:
                                self.debug_derefs(
                                    f"Active object change detected: from {active_object.id} to {other_objs[0].id}")
                                active_object = other_objs[0]
                            else:
                                continue
                    found = False
                    for types, members, obj in active_object.offsetof_types:
                        if types == deref["type"] and members == deref["member"]:
                            # we already have that object
                            self.debug_derefs(
                                f"Active object changed from {active_object.id} to {obj.id}")
                            active_object = obj
                            found = True
                            break
                    if not found:
                        # we need to allocate new TypeUse object for the destination
                        # type of the offsetof operator
                        self.debug_derefs("Creating new offsetof object")
                        # we a assume that we use offsetof to
                        new_object = TypeUse(
                            self.dbops._get_real_type(dst_tid), dst_tid, True)
                        # get a pointer
                        typeuse_objects.append(new_object)
                        new_object.name = self.codegen._get_typename_from_type(
                            self.dbops.typemap[new_object.t_id])
                        self.debug_derefs(
                            f"Generated TypeUse {new_object}")
                        active_object.offsetof_types.append(
                            (deref["type"], deref["member"], new_object))
                        new_object.contained_types.append(
                            (deref["type"], deref["member"], active_object))
                        # change active object
                        self.debug_derefs(
                            f"Active object changed from {active_object.id} to {new_object.id}")
                        active_object = new_object
                    else:
                        self.debug_derefs("Using existing offsetof object")
                elif member_data is not None:

                    # check if we refer to the current active object !
                    first_tid = member_data[access_order[0]]["id"]

                    _first_tid = first_tid
                    _active_tid = active_object.t_id
                    if active_object.is_pointer:
                        _first_tid = self.dbops._get_real_type(
                            _first_tid)
                        _active_tid = self.dbops._get_real_type(
                            _active_tid)
                    if first_tid != active_object.t_id and _first_tid != _active_tid:
                        if first_tid in self.deps.dup_types and active_object.t_id in self.deps.dup_types[first_tid]:
                            self.debug_derefs("dup")
                            pass
                        elif _first_tid in self.deps.dup_types and _active_tid in self.deps.dup_types[_first_tid]:
                            self.debug_derefs("dup")
                            pass
                        else:
                            prev_cast_found = False
                            for _t_id, _original_tid, _is_pointer in active_object.cast_types:
                                self.debug_derefs(
                                    f"Checking cast history {_t_id} {_original_tid} {_is_pointer}")
                                if _first_tid == _t_id or _first_tid == _original_tid or first_tid == _t_id or first_tid == _original_tid:
                                    prev_cast_found = True
                                    break
                            if prev_cast_found:
                                self.debug_derefs(
                                    "Phew, we've found the previous cast that matches the type id")
                            else:
                                # one last check would be to see if there is a single type match among the active
                                # objects -> this trick is aimed at helping in a situation where the sequence of
                                # dereferences is non-monotonic - e.g. we get a pointer, store it in a variable
                                # then we use another pointer and get back to the first one;
                                # a heavier approach to this problem would be to perform some sort of data flow or variable
                                # name tracking; what we do here is to assume that if we have a single matching type, it's probably
                                # one of the objects we already created

                                other_objs = self._match_obj_to_type(
                                    first_tid, typeuse_objects)
                                if len(other_objs) == 1:
                                    self.debug_derefs(
                                        f"Active object change detected: from {active_object.id} to {other_objs[0].id}")
                                    active_object = other_objs[0]

                                else:
                                    self.debug_derefs(
                                        f"Active object id is {active_object.t_id} {_active_tid}, and id is {first_tid} {_first_tid}")
                                    continue
                    self.debug_derefs(
                        f"access order is {access_order}")
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
                                    self.debug_derefs(
                                        f"Active object changed from {active_object.id} to {active_object.used_members[active_tid][member_no].id}")
                                    active_object = active_object.used_members[active_tid][member_no]
                                    self.debug_derefs(
                                        "Member detected in used members")
                                else:
                                    # check if the member is present in the contained types:
                                    # if yes, use the existing object
                                    offsetof_found = False
                                    for types, members, obj in active_object.contained_types:
                                        if types[-1] == t_id and member_no == members[-1]:
                                            self.debug_derefs(
                                                "This member was used in a prior offsetof")
                                            if active_tid not in active_object.used_members:
                                                active_object.used_members[active_tid] = {
                                                }
                                            active_object.used_members[active_tid][member_no] = obj
                                            self.debug_derefs(
                                                f"Active object changed from {active_object.id} to {obj.id}")
                                            active_object = obj
                                            offsetof_found = True
                                    if offsetof_found:
                                        continue
                                    self.debug_derefs(
                                        "Creating new member")
                                    # no -> we create a new object
                                    new_object = TypeUse(self.dbops._get_real_type(
                                        member_tid), member_tid, self.dbops.typemap[member_tid]["class"] == "pointer")
                                    typeuse_objects.append(new_object)
                                    new_object.name = self.codegen._get_typename_from_type(
                                        self.dbops.typemap[new_object.t_id])
                                    self.debug_derefs(
                                        f"Generated TypeUse {new_object}")

                                    active_type = self.dbops.typemap[active_tid]
                                    obj_type = self.dbops.typemap[t_id]
                                    if active_type["class"] == "record_forward" and active_tid != t_id and obj_type["class"] == "record":
                                        self.debug_derefs(
                                            f"Updating object type from record fwd to record {active_tid} -> {t_id}")
                                        for k in active_object.used_members.keys():
                                            if k == obj.t_id:
                                                active_object.used_members[t_id] = active_object.used_members[k]
                                        active_object.t_id = t_id
                                        active_object.original_tid = t_id

                                    # take a note that the member is used
                                    if active_object.t_id not in active_object.used_members:
                                        active_object.used_members[active_object.t_id] = {
                                        }
                                    active_object.used_members[active_object.t_id][member_no] = new_object
                                    # update active object
                                    self.debug_derefs(
                                        f"Active object changed from {active_object.id} to {new_object.id}")
                                    active_object = new_object
            ret_val.append((t_id, base_obj))
            self.typeuse_obj_db += typeuse_objects

        return ret_val

    # -------------------------------------------------------------------------

    # return True if the type if is void*, False otherwise
    # @belongs: init

    def _is_void_ptr(self, t):
        if t is None:
            logging.error(f"Type {t} not found")
            return False
        t = self.dbops._get_typedef_dst(t)

        if t["class"] != "pointer":
            return False

        # we know it's a pointer
        dst_tid = t["refs"][0]
        dst_t = self.dbops.typemap[dst_tid]
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
    # @belongs: init
    def _is_member_in_use(self, type, type_name, member_idx):
        if type["class"] != "record":
            return True

        field_name = type["refnames"][member_idx]

        used_type = self.used_types_data.get(type["id"])

        if used_type is None:
            return False

        if "usedrefs" not in used_type or member_idx >= len(used_type["usedrefs"]):
            logging.warning(f"Unable to check if {field_name} is used or not")
            return True

        if -1 == used_type["usedrefs"][member_idx]:
            if self.args.debug_vars_init:
                logging.info(
                    f"Detected that field {field_name} in {type_name} is not used")
            return False

        return True

    # -------------------------------------------------------------------------

    # @belongs: init
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
    # @belongs: init
    def _get_cast_from_deref(self, deref, f):
        if deref["kind"] == "offsetof":
            return None
        cast_tid = -1
        ret_val = None

        # TODO: implement "kind": "return" -> in that case we don't need to have
        # cast in the offsetrefs
        self.debug_derefs(f"get cast from deref: {deref}")

        # first, check if we are not doing pointer arithmetic
        if deref["kind"] == "assign" and deref["offset"] != 21:
            self.debug_derefs(
                f"skipping deref associated with arithmetic {deref}")

        elif "offsetrefs" in deref:
            for oref in deref["offsetrefs"]:
                src_tid = -1
                src_root_tid = -1
                src_member = -1
                dst_deref = None
                if "cast" in oref:

                    # get the type we are casting to
                    cast_tid = oref["cast"]
                    cast_type = self.dbops.typemap[cast_tid]
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
                        self.debug_derefs(f"dst deref is {dst_deref}")

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
                        local = None
                        for l in f["locals"]:
                            if l["id"] == oref["id"]:
                                local = l
                                break
                        src_tid = local["type"]
                        # logging.error(
                        #    f"Unsupported deref type {oref['kind']}")
                        # continue

                    elif oref["kind"] == "parm":
                        local = None
                        for l in f["locals"]:
                            if l["id"] == id:
                                local = l
                                break
                        dst_deref = local

                    elif oref["kind"] == "callref":
                        # this happens when a return value of a function is casted to other type
                        dst_deref = None
                        # the source type in this case is the return type of the function
                        call_id = f["calls"][oref["id"]]
                        call = self.dbops.fnidmap[call_id]
                        if call is None:
                            self.debug_derefs(
                                f"Call not found in functions")
                            continue
                        src_tid = call["types"][0]

                        if deref["kind"] == "return":
                            cast_tid = f["types"][0]  # return type goes first
                            cast_type = self.dbops.typemap[cast_tid]
                            src_tid = oref["cast"]
                        elif deref["kind"] == "init":
                            # let's assume that the first oref is the
                            inited = deref["offsetrefs"][0]
                            # value that is being initialized
                            if inited["kind"] == "local":
                                local = None
                                for l in f["locals"]:
                                    if l["id"] == inited["id"]:
                                        local = l
                                        break
                                cast_tid = local["type"]
                                cast_type = self.dbops.typemap[cast_tid]
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
                            src_tid = self.dbops._get_real_type(src_tid)
                        else:
                            # kind == parm
                            src_root_tid = dst_deref["type"]
                            src_tid = self.dbops._get_real_type(
                                dst_deref["type"])

                    src_type = self.dbops.typemap[src_tid]
                    src_root_type = src_type
                    # member is only meaningful for records
                    if src_type["class"] == "record":
                        # logging.info(f"src_tid = {src_tid} src_member = {src_member} dst_deref = {dst_deref} deref = {deref}")
                        if src_member != -1:
                            src_member_tid = src_type["refs"][src_member]
                            src_type = self.dbops.typemap[src_member_tid]
                        else:
                            src_member = Init.CAST_PTR_NO_MEMBER
                    else:
                        src_member = Init.CAST_PTR_NO_MEMBER

                    # let's check if the source and destination type don't have the same root:
                    dst_root = self.dbops._get_real_type(cast_tid)
                    if src_member == Init.CAST_PTR_NO_MEMBER:
                        if src_tid in self.deps.dup_types:
                            found = False
                            for t_id in self.deps.dup_types[src_tid]:
                                if t_id == dst_root:
                                    found = True
                                    break
                            if found:
                                continue
                        elif src_tid == dst_root:
                            continue
                    else:
                        src_root = self.dbops._get_real_type(src_member_tid)
                        if src_root in self.deps.dup_types:
                            found = False
                            for t_id in self.deps.dup_types[src_root]:
                                if t_id == dst_root:
                                    found = True
                                    break
                            if found:
                                continue
                        elif src_root == dst_root:
                            continue

                    if src_tid != cast_tid:
                        # last checks: see if we are not dealing with typedefs pointing to the same type:
                        if src_member == Init.CAST_PTR_NO_MEMBER:
                            src_no_typedef = self.dbops._get_typedef_dst(
                                self.dbops.typemap[src_root_tid])["id"]
                        else:
                            src_no_typedef = self.dbops._get_typedef_dst(
                                self.dbops.typemap[src_member_tid])["id"]
                        dst_no_typedef = self.dbops._get_typedef_dst(
                            self.dbops.typemap[cast_tid])["id"]
                        if src_no_typedef == dst_no_typedef:
                            self.debug_derefs(
                                f"source {src_tid} same as dst type {cast_tid}")
                            # sys.exit(1)
                            continue
                        # see if the size of source and dst type matches
                        # caveat: there could be a cast like this : int* ptr = (int*)&s->member
                        # member coult be u16 but its address used to process data as int - we currently
                        # don't support that scheme -> TBD
                        # src_size = self.dbops.typemap[src_no_typedef]["size"]
                        if src_member == Init.CAST_PTR_NO_MEMBER:
                            src_size = self.dbops.typemap[self.dbops._get_typedef_dst(
                                self.dbops.typemap[src_root_tid])["id"]]["size"]
                        else:
                            src_size = self.dbops.typemap[self.dbops._get_typedef_dst(
                                self.dbops.typemap[src_member_tid])["id"]]["size"]

                        dst_size = self.dbops.typemap[dst_no_typedef]["size"]
                        if src_size != dst_size:
                            self.debug_derefs(
                                f"Source {src_root_tid}:{src_size} and dst {dst_no_typedef}:{dst_size} type size mismatch - skipping cast")
                            # sys.exit(1)
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
                if src_tid in self.deps.dup_types:
                    dups = self.deps.dup_types[src_tid]
                    for dup in dups:
                        if dup not in ret_val:
                            ret_val[dup] = copy.deepcopy(ret_val[src_tid])

        return ret_val

    # -------------------------------------------------------------------------

    # If there is an offsetof expression in the deref, return the associated data,
    # return None if no offsetof has been found
    # @belongs: init
    def _get_offsetof_from_deref(self, deref):

        if deref["kind"] != "offsetof":
            return None

        # it's a heuristic, but let's assume that when we use offsetof we actually mean to get from one type to another
        # in other words, let's treat it as a form of type cast

        dst_tid = deref["type"][0]

        # we are only interested in the last member, last type
        member_no = deref["member"][-1]
        src_tid = self.dbops.typemap[deref["type"][-1]]["refs"][member_no]

        ret_val = {}
        ret_val[src_tid] = [(deref["type"], deref["member"])]

        # take care of the duplicates:
        if src_tid in self.deps.dup_types:
            dups = self.deps.dup_types[src_tid]

            for dup in dups:
                if dup not in ret_val:
                    ret_val[dup] = copy.deepcopy(ret_val[src_tid])

        return ret_val

    # -------------------------------------------------------------------------

    # if there is a member access in the deref, return the associated data,
    # return None if no member access has been found
    # @belongs: init
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
            t = self.dbops.typemap[t_id]
            if deref["access"][mi] == 1:
                t_id = self.dbops._get_typedef_dst(t)['id']
                t_id = self.dbops._get_real_type(t_id)
                t = self.dbops.typemap[t_id]
            t = self.dbops._get_typedef_dst(t)
            t_id = t["id"]
            item = None
            if t_id not in ret_val:
                # we create a deep copy in order to avoid
                # interfering with the db cache
                # TODO: ugly, but temporary
                if hasattr(t, "json"):
                    item = t.json()
                else:
                    item = copy.deepcopy(t)
                ret_val[t_id] = item
                # we will update the "usedrefs information"
                for i in range(len(item["usedrefs"])):
                    item["usedrefs"][i] = -1
                # logging.debug(f"processing deref {d}, t_id={t_id}, item={item}")
            else:
                item = ret_val[t_id]

            access_order.append(t_id)

            # let's make a note that the member is used
            member_id = deref["member"][mi]
            t_id = t["refs"][member_id]

            if item["usedrefs"][member_id] != -1 and item["usedrefs"][member_id] != t_id:
                logging.error(
                    f"This member had a different id: t_id={t_id}, member_id={member_id}, prev={item['usedrefs'][member_id]}, curr={t_id}")
                raise Exception("Breaking execution due to error")

            item["usedrefs"][member_id] = t_id

            # if the used member is a record itself, let's add it to the map in order
            # to mark that the type is used (this can help if we have a record type without any member usages)
            t_id = self.dbops._get_real_type(t_id)
            t = self.dbops.typemap[t_id]
            t = self.dbops._get_typedef_dst(t)
            t_id = t["id"]

            if t["class"] == "record" and t_id not in ret_val:
                # we create a deep copy in order to avoid
                # interfering with the db cache
                # TODO: ugly, but temporary
                if hasattr(t, "json"):
                    item = t.json()
                else:
                    item = copy.deepcopy(t)
                ret_val[t_id] = item
                # we will update the "usedrefs information"
                for i in range(len(item["usedrefs"])):
                    item["usedrefs"][i] = -1

        # merge data from type dups
        for t_id in list(ret_val.keys()):
            if t_id in self.deps.dup_types:
                t = ret_val[t_id]
                dups = self.deps.dup_types[t_id]

                for dup in dups:
                    if dup in ret_val:
                        t2 = ret_val[dup]
                        for i in range(len(t["usedrefs"])):
                            if t["usedrefs"][i] != -1 and t2["usedrefs"][i] == -1:
                                t2["usedrefs"][i] = t["usedrefs"][i]
                            if t["usedrefs"][i] == -1 and t2["usedrefs"][i] != -1:
                                t["usedrefs"][i] = t2["usedrefs"][i]

        # take type dups into account
        for t_id in list(ret_val.keys()):
            if t_id in self.deps.dup_types:
                dups = self.deps.dup_types[t_id]
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
    # @belongs: init
    def _discover_casts(self, functions):

        for f_id in functions:

            f = self.dbops.fnidmap[f_id]
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
                                            self.casted_pointers[src_tid][src_member].append(
                                                cast_tid)
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
                                    self.offset_pointers[src_tid].append(
                                        (types, members))
                    # offsetpointers is a map that links internal types to their containing structures

        logging.info(
            f"We discovered the following void pointers cast data {self.casted_pointers}")

    # -------------------------------------------------------------------------

    # @belongs: init
    def _get_used_types_data(self):
        self.used_types_data = {}
        # at this point we know all the functions that are going to be a part of the off-target
        # based on that information let's find out which members of the structural types (records and unions) are used
        # we are going to leverage that information for a smarter, more focused data initialization

        logging.info("Capturing used types information")
        for f_id in self.cutoff.internal_funcs:
            f = self.dbops.fnidmap[f_id]
            if f is None:
                continue  # that's a funcdecl or unresolved func (unlikely)

            # we will extract the member usage from the "derefs" data
            if "derefs" not in f:
                continue

            for d in f["derefs"]:
                member_data, _ = self._get_member_access_from_deref(d)

                if member_data is None:
                    continue

                for t_id in member_data:
                    if t_id not in self.used_types_data:
                        self.used_types_data[t_id] = member_data[t_id]
                        continue

                    for i, used in enumerate(member_data[t_id]["usedrefs"]):
                        if "usedrefs" not in self.used_types_data[t_id]:
                            logging.error(f"usedrefs not found in type {t_id}")

                        if used != -1:
                            self.used_types_data[t_id]["usedrefs"][i] = used

        logging.info(
            f"Used types data captured, size is {len(self.used_types_data)}"
        )

    # -------------------------------------------------------------------------

    # @belongs: init
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
                self._debug_print_typeuse_obj(
                    obj.used_members[_type_id][member_id], visited)
        for _type_id, member, _obj in obj.offsetof_types:
            self._debug_print_typeuse_obj(_obj, visited)

    # -------------------------------------------------------------------------

    # @belongs: codegen or init (used in init but more utility/generic kind)
    def _get_const_array_size(self, type):
        if type["class"] == "incomplete_array" and type["size"] == 0:
            return 0

        elem_type = type["refs"][0]
        elem_size = self.dbops.typemap[elem_type]["size"]
        if elem_size != 0:
            return type["size"] // elem_size
        else:
            return 0

    # -------------------------------------------------------------------------

    # @belongs: init/codegen -> in the end it would be the best to have the metadata generated by init and the code generation done by codegen
    def _generate_var_deinit(self, var):
        return f"aot_memory_free_ptr(&{var});\n"

    # -------------------------------------------------------------------------

    def add_global_init_data(self, name, id, data):
        entry = { 'id': id, 'name': name, 'data': data}
        self.init_data["globals"].append(data)

    # -------------------------------------------------------------------------

    def add_func_init_data(self, name, id, data):
        entry = { 'id': id, 'name': name, 'data': data}
        self.init_data["funcs"].append(data)

    # -------------------------------------------------------------------------

    def dump_init_data(self):
        logging.info("Will dump init data")
        logging.info(f"{self.init_data}")
        with open(f"{self.args.output_dir}/{self.args.dump_init}", "w") as file:
            json.dump(self.init_data, file)
