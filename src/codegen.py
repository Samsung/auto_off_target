#!/usr/bin/env python3

# Auto off-target PoC
###
# Copyright  Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland


#
# Code generation module
#

import logging
import os
import sys
import collections
import difflib
import json
import re

class CodeGen:
    # this is a special value returned by function stubs returning a pointer
    # it's supposed to be easily recognizable (407 == AOT)
    # the value needs to be in sync with what we set in fuzz_lib
    AOT_SPECIAL_PTR = 0x40710000
    AOT_SPECIAL_PTR_SEPARATOR = 0x1000

    VERIFY_STRUCT_LAYOUT_TEMPLATE = "vlayout.c.template"
    VERIFY_STRUCT_LAYOUT_SOURCE = "vlayout.c"
    VERIFY_STRUCT_TYPE_LAYOUT_BLACKLIST = set(["__builtin_va_list", "va_list"])
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

    # {0} - function variable name
    # {1} - function trigger basename
    # {2} - extended root pointer name
    # {3} - function variable type in text form
    DYNAMIC_INIT_FUNCTION_VARIABLE_TEMPLATE = """
    /* Dynamically initialize variable '{0}' using kflat */
    void* {1}_{0}_ptr = aot_kflat_root_by_name("{2}", (void*) 0);
    if({1}_{0}_ptr)
      {0} = ({3}) {1}_{0}_ptr;
    else
      puts("[Unflatten] Failed to load local variable {2}");
"""

    def __init__(self, dbops, deps, cutoff, args):
        self.dbops = dbops
        self.deps = deps
        self.cutoff = cutoff
        self.args = args

        self.generated_functions = 0
        self.generated_stubs = 0
        self.unrolled_simple_macro_counter = 0
        self.struct_types = []
        self.stubs_with_asm = set()
        self.stub_to_return_ptr = {}
        # For each non-inline function generated in the AoT there is a mapping that maps
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

        self.funcs_with_asm = {}

        # The same as above but for the library functions available in the 'aot_lib.c' file used in the AoT
        self.lib_function_pointer_stubs = set()

    def set_init(self, init):
        self.init = init

    def set_otgen(self, otgen):
        self.otgen = otgen

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
            dst_type = self.dbops.typemap[type["refs"][0]]
            name = "* {}".format(name)
            str += self._generate_var_def(dst_type, name)
        elif cl == "const_array":
            dst_type = self.dbops.typemap[type["refs"][0]]
            dst_size = dst_type["size"]
            if dst_size != 0:
                const_size = int(type["size"] / dst_size)
            else:
                const_size = 0
            name = "{}[{}]".format(name, const_size)
            str += self._generate_var_def(dst_type, name)
        elif cl == "pointer":
            dst_type = self.dbops.typemap[type["refs"][0]]
            name = "* {}".format(name)
            str += self._generate_var_def(dst_type, name)
        else:
            logging.error(
                "Unable to generate var def {} for class {}".format(name, cl))
            raise Exception("Breaking exection due to error")
        if str[-1] != ";":
            str += ";"
        return str

    # -------------------------------------------------------------------------

    # Removes 'const' qualifier from the variable definition
    # @belongs: codegen
    def _vardecl_remove_const_qualifier(self, def_str):
        i = def_str.find("=")
        if i > 0:
            def_str_proper = def_str[:i]
            def_str_init = def_str[i:]
        else:
            def_str_proper = def_str
            def_str_init = ""
        if "const " in def_str_proper:
            def_str_proper = def_str_proper.replace("const ", "")
            def_str = def_str_proper+def_str_init
        return def_str

    # -------------------------------------------------------------------------

    # @belongs: codegen
    def _get_type_decls(self, types):
        str = ""
        types_data = self.dbops.typemap.get_many(list(types))

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

    # @belongs: codegen
    def _get_type_defs(self, types, funcs_in_types=None, fid=None, static_funcs=None):
        str = {}
        failed_count = 0

        type_classes = set(["class", "enum", "enum_forward",
                            "record", "record_forward", "typedef"])

        multi_typedefs = set()
        types_data = self.dbops.typemap.get_many(list(types))
        for t in types_data:
            typedef_special = False
            add_names = ""
            tid = t["id"]

            if t["class"] not in type_classes:
                continue

            if t["class"] == "record" and self.args.verify_struct_layout:
                self.struct_types.append(t)

            if t["class"] == "typedef" and self.args.verify_struct_layout:
                resolved_type = self.dbops._get_typedef_dst(t)
                if resolved_type["class"] == "record":
                    self.struct_types.append(t)

            if t["class"] == "typedef" and "decls" in t and len(t["decls"]) != 0:
                # assuming a typedef has exactly one ref
                dst_tid = t["refs"][0]

                if dst_tid in self.deps.identical_typedefs and len(self.deps.identical_typedefs) > 1:
                    if dst_tid not in multi_typedefs:
                        multi_typedefs.add(dst_tid)
                        typedef_special = True
                        for id in self.deps.identical_typedefs[dst_tid]:
                            if id == tid:
                                continue
                            if id in types:
                                add_names += f", {self.dbops.typemap[id]['name']}"
                    else:
                        continue

            if "def" not in t:
                logging.error("def not in {}".format(t))
            if self.args.used_types_only and "useddef" in t:
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
                    str[tid] += self._get_func_decls(
                        fid, funcs_in_types[tid], [], section_header=False)

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

    def _is_excluded_func(self, fid):
        if fid in self.dbops.lib_funcs_ids:
            return True
        elif fid in self.dbops.builtin_funcs_ids:
            return True
        elif fid in self.dbops.replacement_funcs_ids:
            return True
        return False

    # @belongs: codegen
    def _get_func_decls(self, fid, functions, static_functions=[], section_header=True):
        str = ""
        # if section_header:
        #    str += "\n\n/* ----------------------------- */\n" +\
        #        "/* Function declarations section */\n" +\
        #        "/* ----------------------------- */\n"
        funcs = [f for f in functions if self.dbops.fnidmap[f] is not None and self._is_excluded_func(f) is False]
        # a function cannot be func and funcdelc at the same time
        remaining = [f for f in functions if f not in funcs and self._is_excluded_func(f) is False]
        funcdecls = [f for f in remaining if self.dbops.fdmap[f] is not None and self._is_excluded_func(f) is False]

        attributes = ""

        # there is one special case in funcs: inline functions with external linkage
        # those should be declared as non-inline in multiple places and keep inline
        # definition in their corresponding source file
        for f in funcs:
            if f not in static_functions:

                if f in self.otgen.ot_funcs:
                    attributes = "__attribute__ ((tainted_args))"
                else:
                    attributes = ""
                func = self.dbops.fnidmap[f]
                decl = func["declbody"]
                if f in self.dbops.lib_funcs_ids:
                    decl = decl.replace("static ", "extern ")
                if "inline" in func and func["inline"] and func["linkage"] == "external":
                    if decl.startswith("inline "):
                        decl = decl.replace("inline ", "")
                decl = self._filter_out_asm_in_fdecl(decl)
                decl = decl.replace(
                    '__attribute__((warn_unused_result("")))', "")
                decl = decl.replace(
                    '__attribute__((overloadable))', "")
                decl = decl.replace(
                    '__attribute__((always_inline))', "")
                decl = re.sub(r"__attribute__\(\(pass_object_size\(\d+\)\)\)", "", decl)  
                str += self._get_func_clash_ifdef(f, fid, True)
                str += f"\n\n{decl}{attributes};\n"
                str += self._get_func_clash_endif(f, fid)

        str += "\n// Func decls\n"
        for f in funcdecls:
            if f not in static_functions:
                func = self.dbops.fdmap[f]
                decl = func["decl"]
                if f in self.dbops.lib_funcs_ids:
                    decl = decl.replace("static ", "extern ")
                decl = self._filter_out_asm_in_fdecl(decl)
                decl = decl.replace(
                    '__attribute__((warn_unused_result("")))', "")
                decl = decl.replace(
                    '__attribute__((overloadable))', "")
                decl = decl.replace(
                    '__attribute__((always_inline))', "")
                decl = re.sub(r"__attribute__\(\(pass_object_size\(\d+\)\)\)", "", decl)  
                str += self._get_func_clash_ifdef(f, fid, True)
                str += f"\n\n{decl};\n"
                str += self._get_func_clash_endif(f, fid)

        for f_id in static_functions:
            if f_id in self.otgen.static_inline_headers:
                # for static inline functions we don't generate wrappers
                # as the entire function's body is located in the header file
                # note: the keys of the static_inline_headers dict are in fact the
                # ids of static inline functions
                continue
            if f_id in self.otgen.ot_funcs:
                attributes = "__attribute__ ((tainted_args))"
            else:
                attributes = ""

            f = self.dbops.fnidmap[f_id]
            name = f["name"]
            str += self._get_func_clash_ifdef(f_id, fid, True)
            str += "\n\n"
            body = f["declbody"].replace(
                "{}(".format(name), "wrapper_{}_{}(".format(name, f_id))
            body = body.replace("static ", "")
            body = body.replace("inline ", "")
            body = self._filter_out_asm_in_fdecl(body)
            body = body.replace('__attribute__((warn_unused_result("")))', "")
            body = body.replace('__attribute__((overloadable))', "")
            body = body.replace('__attribute__((always_inline))', "")
            body = re.sub(r"__attribute__\(\(pass_object_size\(\d+\)\)\)", "", body)
            str += "{};\n".format(body)
            body = f["declbody"]
            body = self._filter_out_asm_in_fdecl(body)
            body = body.replace('__attribute__((warn_unused_result("")))', "")
            body = body.replace('__attribute__((overloadable))', "")
            body = body.replace('__attribute__((always_inline))', "")
            body = re.sub(r"__attribute__\(\(pass_object_size\(\d+\)\)\)", "", body)  

            str += "{}{};\n".format(body, attributes)
            str += self._get_func_clash_endif(f_id, fid)
        return str

    # -------------------------------------------------------------------------

    def _flush_function_code(self,func_data_list,common_unrolled_macro_map):
        str = ""
        # First flush the common unrolled macro definitions for macros with arguments
        for k,v in common_unrolled_macro_map.items():
            str += f"#define {k} {v}\n\n"
        # Fill the 'str' with function bodies and unrolled macro definitions
        used_simple_macros = {}
        for unrolled_fbody_text,unique_unrolled_macro_map in func_data_list:
            for k,v in unique_unrolled_macro_map.items():
                if k in used_simple_macros and used_simple_macros[k]!=v:
                    str += f"#undef {k}\n"
                str += f"#define {k} {v}\n"
                used_simple_macros[k] = v
            str += "\n" + unrolled_fbody_text + "\n\n"
        return str

    def _get_unique_unrolled_macro_map(self,unrolled_macro_map):
        unique_unrolled_macro_map = {}
        for k,v in unrolled_macro_map.items():
            if len(set([x[0] for x in v]))>1: # unlikely
                """
                We can have the same non-argument macro in a function with different values; consider:
                void fun() {
                #define CONSTVAL 3
                (...)
                #undef CONSTVAL
                #define CONSTVAL 4
                (...)
                }
                """
                for x in v:
                    unique_unrolled_macro_map[f"{k}__{x[1]}"] = x[0]
            else:
                unique_unrolled_macro_map[k] = v[0][0]
        return unique_unrolled_macro_map

    # Gets the function body with unrolled macro definitions (for the purpose of improving code readibility)
    # Fills the 'unrolled_macro_map' and 'common_unrolled_macro_map' collections upon execution
    # Returns the unrolled function body or None if function is not supported or error occurs
    def _get_unrolled_macro_body(self,f_entry,unrolled_macro_map,common_unrolled_macro_map):
        if not self.args.unroll_macro_defs or len(f_entry["macro_expansions"])<=0:
            return None
        out_body = ""
        body_loc = list()
        pos = 0
        size = 0
        for i,mexp_entry in enumerate(f_entry["macro_expansions"]):
            npos = mexp_entry["pos"]
            if npos<pos+size:
                # Ignore overlapping macro expansion entries
                continue
            out_body+=f_entry["unpreprocessed_body"][pos+size:npos]
            pos = npos
            size = mexp_entry["len"]
            macro_str = f_entry["unpreprocessed_body"][pos:pos+size]
            if mexp_entry["text"]=='':
                # We just remove a part of the original code
                continue
            u = macro_str.find('(')
            if u>=0:
                macro_replacement_name = f"__macrocall__{macro_str[:u].strip()}__{self.unrolled_simple_macro_counter}"
                macro_replacement_call = f"{macro_replacement_name}/*({macro_str[u+1:-1].replace('/*','|*').replace('*/','*|')})*/"
                if macro_replacement_name in common_unrolled_macro_map: # unlikely
                    logging.warning(f"Duplicated entry in the unrolled macro map: {macro_replacement_name}")
                    return None
                common_unrolled_macro_map[macro_replacement_name] = mexp_entry["text"]
                self.unrolled_simple_macro_counter+=1
                out_body+=macro_replacement_call
            else:
                if macro_str in unrolled_macro_map:
                    unrolled_macro_map[macro_str].append((mexp_entry["text"],self.unrolled_simple_macro_counter))
                else:
                    unrolled_macro_map[macro_str] = [(mexp_entry["text"],self.unrolled_simple_macro_counter)]
                self.unrolled_simple_macro_counter+=1
                # (location of macro in the body, length of macro string, index of macro string in macro vector)
                body_loc.append((len(out_body),len(macro_str),len(unrolled_macro_map[macro_str])-1))
                out_body+=macro_str
        out_body+=f_entry["unpreprocessed_body"][pos+size:]
        # Replace macro strings in case of simple macros with distinct values
        body_shift=0
        for bloc,mlen,mindex in body_loc:
            k = out_body[bloc+body_shift:bloc+body_shift+mlen]
            if len(set([x[0] for x in unrolled_macro_map[k]]))>1:
                text,cntr = unrolled_macro_map[k][mindex]
                nk = f"{k}__{cntr}"
                out_body = out_body[:bloc+body_shift]+nk+out_body[bloc+body_shift+mlen:]
                body_shift+=len(nk)-mlen
        # Replace function header from preprocessed body
        body_header_end = f_entry["body"].find("{")
        header = f_entry["body"][0:body_header_end]
        out_body_header_end = out_body.find("{")
        return header + out_body[out_body_header_end:]


    # @belongs: codegen
    def _get_func_defs(self, fid, functions, section_header=True, stubs=False, file=""):
        str = ""
        # if section_header:
        #    str += "\n\n/* ----------------------------- */\n" +\
        #        "/* Function definitions section  */\n" +\
        #        "/* ----------------------------- */\n"
        if stubs is False:
            # Collection of generated macro definitions that replaces the expanded code in the preprocessed code
            common_unrolled_macro_map = {}
            # [(function_id,unrolled_function_body_text,unique_unrolled_macro_map),...]
            func_data_list = list()
            for f_id in functions:
                tmp = ""
                unrolled_macro_map = {}
                if self.dbops.fnidmap[f_id] is not None:
                    tmp += self._get_func_clash_ifdef(f_id, fid)
                    if f_id not in self.cutoff.external_funcs:
                        if not self.args.dbjson2:
                            f_entry = self.dbops.fnidmap[f_id]
                            out_body = self._get_unrolled_macro_body(f_entry,unrolled_macro_map,common_unrolled_macro_map)
                            if out_body is None:
                                out_body = f_entry["body"]
                            tmp += self._filter_out_asm_inlines(
                                f_id, out_body, file)
                        else:
                            tmp += self._filter_out_asm_inlines(
                                f_id, self.dbops.fnidmap[f_id]["unpreprocessed_body"], file)
                        self.generated_functions += 1
                        # if we define a function we don't need to have the extern specifier
                        tmp = tmp.replace("extern ", "", 1)
                        if self.args.dynamic_init and ("inline" not in self.dbops.fnidmap[f_id] or self.dbops.fnidmap[f_id]["inline"] is not True):
                            tmp += "\n%s" % (self._get_function_pointer_stub(
                                self.dbops.fnidmap[f_id]))
                    else:
                        # this is not a stubs file but we might have a stub of a static function inside
                        tmp += self._generate_function_stub(
                            f_id, stubs_file=stubs)
                        if (len(tmp) > 0) and (f_id not in self.otgen.static_inline_headers):
                            tmp = self._get_func_decls(
                                fid, [], [f_id], section_header=False) + "\n" + tmp
                    if len(tmp) > 0:
                        tmp += self._get_func_clash_endif(f_id, fid)
                        tmp += "\n\n"
                    # (function_id,unrolled_function_body_text,unique_unrolled_macro_map)
                    tmp = tmp.replace('__attribute__((warn_unused_result("")))', "")
                    tmp = tmp.replace('__attribute__((overloadable))', "")
                    tmp = tmp.replace('__attribute__((always_inline))', "")
                    tmp = re.sub(r"__attribute__\(\(pass_object_size\(\d+\)\)\)", "", tmp)
                    func_data_list.append((tmp, self._get_unique_unrolled_macro_map(unrolled_macro_map)))
            str += self._flush_function_code(func_data_list,common_unrolled_macro_map)
        else:
            for f_id in functions:
                str += self._get_func_clash_ifdef(f_id, fid)
                str += self._generate_function_stub(f_id, stubs_file=stubs)
                str += self._get_func_clash_endif(f_id, fid)
                str += "\n\n"

        return str

    # -------------------------------------------------------------------------

    # @belongs: codegen
    def _getAttrNum(self, RT):
        if "attrnum" in RT:
            return RT["attrnum"]
        else:
            return 0

    # Checks if a given type (depT) depends on the record type RT
    # @belongs: codegen
    def _isAnonRecordDependent(self, RT, depT):
        if RT["id"] == depT["id"]:
            return True
        elif (depT["class"] == "const_array" or depT["class"] == "incomplete_array") and depT["refs"][0] == RT["id"]:
            # struct { u16 index; u16 dist;} near[0];
            return True
        else:
            return False

    # @belongs: codegen
    def _generate_verification_recipes(self):
        verify_recipes = list()
        verify_recipes.append(
            "    /* Here comes autogenerated recipes to verify AoT record types structure layout. Modify at your own peril! */")
        verify_recipes.append(
            "    /* --- Number of generated structs: %d */\n" % (len(self.struct_types)))
        # RT is the record type we are verifying (it can be record or typedef)
        # if RT is originally typedef then TPD will point to the typedef type and RT will collapse to the underlying record type
        # MT is a type of a corresponding member of RT
        # if MT is originally typedef then MTPD will point to the typedef type and MT will collapse to the underlying record type
        for RT in self.struct_types:
            TPD = None
            if RT["class"] == "typedef":
                TPD = RT
                if TPD["name"] in CodeGen.VERIFY_STRUCT_TYPE_LAYOUT_BLACKLIST:
                    continue
                RT = self.dbops._get_typedef_dst(RT)
            if RT["str"] != "" or TPD:
                member_tuples = list()
                if RT["size"] > 0:
                    try:
                        # As of the current quirk of dbjson when there's anonymous record inside a structure followed by a name we will have two entries in "refs"
                        #  but only single entry in "memberoffsets"
                        #   struct X { ... };       // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
                        #   struct X { ... } w;     // ignore "__!recorddecl__" from refs/refnames/usedrefs (present in decls)
                        #   struct { ... };         // "__!anonrecord__" as a normal member (present in decls)
                        #   struct { ... } w;       // ignore "__!anonrecord__" from refs/refnames/usedrefs (present in decls)
                        #  summary: ignore all "__!recorddecl__" from decls and "__!anonrecord__" if there's the same refs entry that follows
                        real_refs = list()
                        ignore_count = 0
                        bitfield_members = set([])
                        if "bitfields" in RT:
                            bitfield_members = set(
                                [int(x) for x in RT["bitfields"].keys()])
                        for i in range(len(RT["refnames"])-self._getAttrNum(RT)):
                            if i in RT["decls"] and (RT["refnames"][i] != "__!anonrecord__" or (i+1 < len(RT["refs"]) and
                                                                                                self._isAnonRecordDependent(self.dbops.typemap[RT["refs"][i]], self.dbops.typemap[RT["refs"][i+1]]))):
                                ignore_count += 1
                                continue
                            else:
                                real_refs.append(
                                    (RT["refs"][i], RT["refnames"][i], RT["memberoffsets"][i-ignore_count], [], [], i in bitfield_members))
                    except Exception as e:
                        sys.stderr.write(json.dumps(RT, indent=4)+"\n")
                        raise e
                    while len(real_refs) > 0:
                        ref, name, offset, memberoffset_list, refname_prefix_list, is_bitfield = real_refs.pop(
                            0)
                        MT = self.dbops.typemap[ref]
                        if MT["class"] == "typedef":
                            MTPD = MT
                            MT = self.dbops._get_typedef_dst(MT)
                        if MT["class"] == "record":
                            if MT["size"] > 0:
                                internal_real_refs = list()
                                ignore_count = 0
                                bitfield_members = set([])
                                if "bitfields" in MT:
                                    bitfield_members = set(
                                        [int(x) for x in MT["bitfields"].keys()])
                                for i in range(len(MT["refnames"])-self._getAttrNum(MT)):
                                    if i in MT["decls"] and (MT["refnames"][i] != "__!anonrecord__" or (i+1 < len(MT["refs"]) and
                                                                                                        self._isAnonRecordDependent(self.dbops.typemap[MT["refs"][i]], self.dbops.typemap[MT["refs"][i+1]]))):
                                        ignore_count += 1
                                        continue
                                    else:
                                        member_list = list()
                                        if name != "__!anonrecord__":
                                            member_list.append(name)
                                        internal_real_refs.append((MT["refs"][i], MT["refnames"][i], MT["memberoffsets"][i-ignore_count],
                                                                   memberoffset_list+[offset], refname_prefix_list+member_list, i in bitfield_members))
                                real_refs = internal_real_refs+real_refs
                        else:
                            member_name = ".".join(refname_prefix_list+[name])
                            member_offset = sum(memberoffset_list+[offset])
                            member_tuples.append(
                                (member_name, member_offset, is_bitfield))
                verify_member_recipes = list()
                for name, offset, is_bitfield in member_tuples:
                    if not is_bitfield:
                        verify_member_recipes.append(
                            "        VERIFY_OFFSET(%s,%d);" % (name, offset/8))
                    else:
                        verify_member_recipes.append(
                            "        /* Ignore verification of bitfield %s */" % (name))
                if TPD:
                    verify_recipes.append(CodeGen.VERIFY_STRUCT_TYPE_TEMPLATE % (
                        TPD["name"], RT["size"]/8, "\n".join(verify_member_recipes)))
                elif RT["union"] is False:
                    verify_recipes.append(CodeGen.VERIFY_STRUCT_TEMPLATE % (
                        RT["str"], RT["size"]/8, "\n".join(verify_member_recipes)))
                else:
                    verify_recipes.append(CodeGen.VERIFY_UNION_TEMPLATE % (
                        RT["str"], RT["size"]/8, "\n".join(verify_member_recipes)))
        return verify_recipes

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
    # @belongs: codegen
    def _generate_function_call(self, function_id, static=False, create_params=True, param_names=None, known_type_names=None, new_types=None):
        # in order to generate a correct call we need to know:
        # - returned type
        # - types of function parameters
        # - function name
        function = self.dbops.fnidmap[function_id]
        if self.args.afl == 'stores':
            param_names = ['dev', 'attr', 'buf', 'count']
        elif self.args.afl == 'genl_ops':
            param_names = ['skb', 'info']

        name = function["name"]

        str = "\n// Call site for function '{}'\n".format(name)

        if create_params:
            # put everything in braces to avoid name collision
            str += "{\n"

        # the return type goes first in the "types" array
        type_ids = function["types"][:]
        return_present = True
        first_type = self.dbops.typemap[type_ids[0]]
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

        if name in self.dbops.init_data and param_names is None:
            user_init_data = self.dbops.init_data[name]
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
            logging.debug(
                f"order_to_names {order_to_names} order_to_user_name {order_to_user_name} ")
            order_to_params = {}
            for i in range(1, len(type_ids)):  # 1 -> let's skip the return type
                varname = ""
                if "name" in function["locals"][i-1] and function["locals"][i-1]["parm"]:
                    tmp = function["locals"][i-1]["name"]
                    if tmp != "":
                        varname = function["locals"][i-1]["name"]
                        logging.debug(f"varname is {varname}")
                        for ord in order_to_names:
                            if varname in order_to_names[ord]:
                                order_to_params[ord] = i
                                logging.debug(
                                    f"order_to_params[{ord}] = {i}, tid = {type_ids[i]}")
                                if ord in order_to_user_name:
                                    param_to_user_name[i] = order_to_user_name[ord]
                            else:
                                logging.debug(
                                    f"varname {varname} not in order_to_names[{ord}]")
            logging.debug(f"Order to names: {order_to_names}:")
            logging.debug(f"Order to params: {order_to_params}")
            order_to_params_sorted = collections.OrderedDict(
                sorted(order_to_params.items()))
            logging.debug(f"Order to params sorted: {order_to_params_sorted}")

            partial_order = []

            for ord in order_to_params_sorted:
                partial_order.append(order_to_params_sorted[ord])
            # partial_order now contains selected indices in the type_ids array sorted
            # according to the order found in the user data

            # check if we need to reorder anything
            reorder = False
            for i in range(1, len(partial_order)):
                if partial_order[i] < partial_order[i-1]:
                    reorder = True
                    break

            if reorder:
                to_add = []  # we shall remove those params from the list and add them
                # sorted at the end
                i = 0
                for index in partial_order:
                    to_add.append(type_ids[index])
                    val = index_mapping[index]
                    index_mapping[index] = -1
                    # remember the old index of this param
                    index_mapping[len(type_ids) + i] = val
                    i += 1
                    type_ids[index] = -1  # mark that this param is moved
                for tid in to_add:
                    type_ids.append(tid)
            # index_mapping = {}

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
        alloc = False
        start_index = 0

        if create_params:
            res_var = "_init_res"
            str += "int {} = 0;\n".format(res_var)
            for tid in type_ids:
                type = self.dbops.typemap[tid]
                saved_i = i
                if i == 0 and not return_present:
                    i += 1
                    continue

                if tid == -1:  # this param was reordered
                    i += 1
                    varnames.append("_aot_reordered_param")
                    vartypes.append(type)
                    continue

                varname = ""
                if i == 0:
                    varname += "ret_value"
                else:
                    # if name in self.dbops.init_data and param_names is None:
                    i = index_mapping[i]
                    if param_names is None:
                        # varname += "param_{}".format(i)

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
                    # if self.args.afl == 'stores' and varname in ['buf', 'count']:
                    #     if varname == 'buf':
                    #         fuzz = 1  # arbitrarily turning on fuzzing
                    #         buf_init = f'aot_memory_init_ptr(&buf, 4096, {self.init.ptr_init_size} /* count */, {fuzz} /* fuzz */, 0);'
                    #         str += buf_init
                    #         alloced_vars.append(varname)
                    #         str += "\n"
                    #     elif varname == 'count':
                    #         str += self._load_snippet("stores_var_init")

                    # elif self.args.afl == 'genl_ops' and varname in ['info']:
                    #     alloc = False
                    #     pointers = []
                    #     tmp, alloc = self.init._generate_var_init(
                    #         varname, type, res_var, pointers, known_type_names=known_type_names,
                    #         new_types=new_types, entity_name=name, fuse=0)
                    #     str += tmp
                    #     if alloc:
                    #         alloced_vars.append(varname)
                    #     str += "\n"
                    #     str += self._load_snippet("genl_ops_var_init")

                    #else:

                    dyn_init_present = False
                    if self.args.dynamic_init:

                        RT, TPD = self.init._resolve_record_type(type["id"])
                        if RT is not None and type["class"] == "pointer":
                            dyn_init_present = True

                    alloc = False
                    pointers = []
                    # let's check if the param is used at all, if not, let's skip the init just like that
                    is_used = function["locals"][i-1]["used"]
                    user_init = False
                    if name in self.dbops.init_data:
                        _varname = function["locals"][i - 1]["name"]
                        for item in self.dbops.init_data[name]["items"]:
                            if _varname in item["name"]:
                                user_init = True
                                break

                    if (is_used and not dyn_init_present) or user_init:
                        init_obj = None
                        if function_id in self.otgen.funcs_init_data:
                            init_data = self.otgen.funcs_init_data[function_id]
                            param_tid, init_obj = init_data[i - 1]
                        tmp, alloc, brk = self.init._generate_var_init(
                            varname, type, res_var, pointers, known_type_names=known_type_names, new_types=new_types, entity_name=name,
                            init_obj=init_obj, fuse=0, fid=function_id)
                    elif not dyn_init_present and not is_used:
                        tmp = f"// Detected that the argument {varname} is not used - skipping init\n"
                    elif dyn_init_present:
                        tmp = ""

                    str += tmp
                    str += "\n"

                    if self.args.dynamic_init and dyn_init_present:
                        #RT, TPD = self.init._resolve_record_type(type["id"])
                        #if RT is not None and type["class"] == "pointer":
                        # Replace the initialized variable with the image from kflat
                        vartype = " ".join(self._generate_var_def(
                            type, varname).split()[:-1])
                        str += CodeGen.DYNAMIC_INIT_FUNCTION_VARIABLE_TEMPLATE.format(
                            varname, "flatten", f"_func_arg_{i}", vartype)+"\n\n"
                i = saved_i
                i += 1

            if return_present:
                # varnames[0] -> return var name
                start_index = 1

            # Handle AoT Recall mode
            interface = None
            interface_types = ["read", "write", "show", "store", "ioctl"]
            if name in self.dbops.init_data:
                if "interface" in self.dbops.init_data[name]:
                    interface = self.dbops.init_data[name]["interface"]

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

        if create_params:
            str += "}\n"

        return str

    # -------------------------------------------------------------------------

    # Given a function id, generate a function stub
    # @belongs: codegen
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
            function = self.dbops.fnidmap[function_id]
            t = TYPE_FUNC
            if function is None:
                logging.warning(
                    f"Unable to find function id {function_id}, will try funcdecl")
                function = self.dbops.fdmap[function_id]
                if function is None:
                    logging.warning(
                        f"Unable to find function is {function_id} in funcdecls, trying unresolved")
                    function = self.dbops.umap[function_id]
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
            return_type = self.dbops.typemap[function["types"][0]]
            original_fbody = function["body"][len(decl):]
            original_fbody = original_fbody.replace("{", "", 1)
            before, sep, after = original_fbody.rpartition("}")
            original_fbody = before.replace("\n", "\n\t")
        elif t == TYPE_FUNCDECL or t == TYPE_FPOINTER:
            if t == TYPE_FUNCDECL:
                return_type = self.dbops.typemap[function["types"][0]]
                # we use signature as it guarantees no parameter names
                tmp = function["signature"]
                copy = function["signature"]
                # sometimes it happens that function decl line doesn't have param names
                # let's try to detect that and generate them

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
                    raise Exception("Breaking exection due to error")

                # after the name, we have the function type
                end_index = tmp[index:].find("(") + index
                func_type = tmp[index:end_index]
                index = end_index
            else:
                # in the TYPE_FPOINTER mode, rather than passing id to a function we
                # pass id of a function type
                f_type = self.dbops.typemap[function_id]
                if f_type is None:
                    logging.error(
                        f"Unable to locate function type {function_id}")
                    raise Exception("Breaking exection due to error")
                return_type = self.dbops.typemap[f_type["refs"][0]]

                if stub_name is not None:
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
            i = 0
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
        if function_id in self.dbops.all_funcs_with_asm:
            str += "\t// note: original function's implementation contains assembly\n"
            self.stubs_with_asm.add(func_name)

        # and function_id not in self.dbops.all_funcs_with_asm:
        if static and inline != 1 and not stubs_file:
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

        if return_type is not None:
            orig_return_type = return_type
            orig_cl = return_type["class"]
            return_type = self.dbops._get_typedef_dst(return_type)
            null_pointer = ["pointer", "decayed_pointer", "function",
                            "const_array", "incomplete_array", "variable_array"]
            cl = return_type["class"]
            if cl in null_pointer:
                counter = len(self.stub_to_return_ptr)
                # we return an address from a specially mapped memory region -> see aot_fuzz_lib.c for the details
                # each function stub returns an address separated by a page size (0x1000)
                # this is used to recognize which function stub caused a failure (as further offsets might be applied to the
                # original base address returned by the stub, e.g. ptr = stub(); ptr->member = x;

                if self.args.stubs_for_klee:
                    # NOTE: for KLEE we do  special trick: in order to mark that the failure is caused by
                    # the user data (i.e. lack of stub), we introduce a dummy symbolic object into constraints
                    str += "\t#ifdef KLEE\n"
                    str += "\tint* ptr;\n"
                    str += "\taot_memory_init_ptr((void**) &ptr, sizeof(int), 1, 1, \"stubptr\");\n"
                    str += "\taot_tag_memory(ptr, sizeof(int), 0);\n"
                    str += "\tif (*ptr) {\n"
                    str += "\t\t*ptr = 0;\n"
                    str += "\t}\n"
                    str += "\t#endif\n"

                val = CodeGen.AOT_SPECIAL_PTR + \
                    (counter * (2*CodeGen.AOT_SPECIAL_PTR_SEPARATOR))
                self.stub_to_return_ptr[func_name] = val
                str += f"\treturn ({self._get_typename_from_type(return_type)}){hex(val)}; // returning a special pointer"
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
        if self.args.dynamic_init and (not static or not stubs_file):
            if function is not None and ("inline" not in function or function["inline"] is not True):
                str += "%s\n" % (self._get_function_pointer_stub(function))
        if stubs_file:
            self.generated_stubs += 1
        if t != TYPE_FPOINTER:
            return str
        else:
            return str, func_name

    # -------------------------------------------------------------------------

    # @belongs: codegen
    def _load_snippet(self, name):
        snippet_path = f"{os.path.abspath(os.path.dirname(sys.argv[0]))}/resources/{name}.snippet"

        if not os.path.isfile(snippet_path):
            logging.error(f"Snippet {snippet_path} not found!")
            return f"// Snippet {snippet_path} not found\n"

        with open(snippet_path, "r") as f:
            return f.read() + "\n\n"

    # -------------------------------------------------------------------------
    # For a given function F generates code that initializes global function pointer
    # with its address
    # For example for function 'myfun' in file 'kernel/mm/myfile.c' we should get:
    # 'int (*__pf__kernel__mm__myfile____c__myfun)(void) = myfun;'
    # @belongs: codegen
    def _get_function_pointer_stub(self, function):

        loc = function["location"].split(":")[0]
        fptr_stub_name = "%s__%s" % (loc.replace(
            "/", "__").replace("-", "___").replace(".", "____"), function["name"])
        self.function_pointer_stubs.add((fptr_stub_name, function["id"]))
        fptr_stub_def = "int (*%s)(void) = (int (*)(void))%s;" % (
            fptr_stub_name, function["name"])
        if function["id"] in self.dbops.lib_funcs_ids:
            self.lib_function_pointer_stubs.add(
                (fptr_stub_def, function["id"]))
        return fptr_stub_def

   # -------------------------------------------------------------------------

    # comment out inline assembly code and keep stats
    # @belongs: codegen
    def _filter_out_asm_inlines(self, fid, body, file):
        if self.args.include_asm:
            return body

        tmp = body
        tmp = tmp.replace("asm volatile", "//asm volatile")
        tmp = tmp.replace("asm (", "//asm (")
        tmp = tmp.replace("asm(", "//asm(")

        if tmp != body:
            # we have replaced some inline asm
            diff = difflib.unified_diff(body.split("\n"), tmp.split("\n"), n=0)
            if fid not in self.dbops.known_funcs_ids:
                self.funcs_with_asm[fid] = {"file": file, "diff": diff}

        return tmp

    # -------------------------------------------------------------------------

    # @belongs: codegen
    def _filter_out_asm_in_fdecl(self, decl):
        if not self.args.include_asm and ' asm(' in decl:
            index = decl.find(' asm(')
            end = decl[index:].find(')') + index
            logging.info(
                f"Found asm in function end is {end} copy len is {len(decl)} copy is {decl}")
            if end == len(decl) - 1:
                # the declation end with the asm clause -> that's what we're looking for
                decl = decl[:index] + "/*" + decl[index:end + 1] + "*/"
        return decl

    # -------------------------------------------------------------------------

    # @belongs: codegen?
    def _get_type_clash_ifdef(self, t_id, fid):
        ifdef = ""
        ifgenerated = False
        if t_id in self.deps.clash_type_to_file:
            # if fid in self.clash_type_to_file[t_id]:
            # now we know that this file is using a type that clashes with some other type

            for file_id in self.deps.clash_type_to_file[t_id]:
                if len(ifdef) != 0:
                    ifdef += " && "
                ifdef += f"!defined({self.otgen._get_file_define(file_id)})"

            if len(ifdef) == 0:
                logging.info(f"ifdef len is 0, t_id is {t_id}")
            else:
                ifdef = f"#if {ifdef}\n"
                ifgenerated = True
            if t_id in self.deps.type_clash_nums:
                ifdef += f"#ifndef CLASH_TYPE_{self.deps.type_clash_nums[t_id]}\n"
                ifdef += f"#define CLASH_TYPE_{self.deps.type_clash_nums[t_id]}\n"

        return ifdef, ifgenerated

    # -------------------------------------------------------------------------

    # @belongs: codegen?
    def _get_type_clash_endif(self, t_id, fid, ifgenerated=True):
        endif = ""
        if t_id in self.deps.clash_type_to_file:
            # if fid in self.clash_type_to_file[t_id]:
            if ifgenerated == True:
                endif = "#endif\n"
            if t_id in self.deps.type_clash_nums:
                endif += "#endif\n"

        return endif

    # -------------------------------------------------------------------------

    # @belongs: codegen?
    def _get_global_clash_ifdef(self, g_id, fid):
        ifdef = ""
        if g_id in self.deps.clash_global_to_file:
            # if fid in self.clash_global_to_file[g_id]:
            # now we know that this file is using a global that clashes with some other global

            for file_id in self.deps.clash_global_to_file[g_id]:
                if len(ifdef) != 0:
                    ifdef += " && "
                ifdef += f"!defined({self.otgen._get_file_define(file_id)})"
            ifdef = f"#if {ifdef}\n"
            if g_id in self.deps.glob_clash_nums:
                ifdef += f"#ifndef CLASH_GLOB_{self.deps.glob_clash_nums[g_id]}\n"
                ifdef += f"#define CLASH_GLOB_{self.deps.glob_clash_nums[g_id]}\n"
        return ifdef

    # -------------------------------------------------------------------------

    # @belongs: codegen?
    def _get_global_clash_endif(self, g_id, fid):
        endif = ""
        if g_id in self.deps.clash_global_to_file:
            # if fid in self.clash_global_to_file[g_id]:
            endif = "#endif\n"
            if g_id in self.deps.glob_clash_nums:
                endif += "#endif\n"

        return endif

    # -------------------------------------------------------------------------

    # @belongs: codegen?
    def _get_func_clash_ifdef(self, f_id, fid, isDecl = False):
        ifdef = ""
        marker = "FUNC"
        if isDecl is True:
            marker = "FUNCDECL"
        if f_id in self.deps.clash_function_to_file:
            # if fid in self.clash_function_to_file[f_id]:
            # now we know that this file is using a function that clashes with some other function

            for file_id in self.deps.clash_function_to_file[f_id]:
                if len(ifdef) != 0:
                    ifdef += " && "
                ifdef += f"!defined({self.otgen._get_file_define(file_id)})"
            ifdef = f"#if {ifdef}\n"
            if f_id in self.deps.func_clash_nums:
                ifdef += f"#ifndef CLASH_{marker}_{self.deps.func_clash_nums[f_id]}\n"
                ifdef += f"#define CLASH_{marker}_{self.deps.func_clash_nums[f_id]}\n"

        return ifdef

    # -------------------------------------------------------------------------

    # @belongs: codegen?
    def _get_func_clash_endif(self, f_id, fid):
        endif = ""
        if f_id in self.deps.clash_function_to_file:
            endif = "#endif\n"
        if f_id in self.deps.func_clash_nums:
            endif += "#endif\n"

        return endif

    # @belongs: codegen or ot-generator
    def _get_file_header(self, fid=-1):
        str = "/* ------------------------------------------------ */\n" +\
              "/* AOT generated this file                          */\n" +\
              "/* ------------------------------------------------ */\n"
        if int(fid) >= 0:
            str += "/* Original file path: " + self.dbops.srcidmap[int(fid)] + " */\n\n"

        return str

    # -------------------------------------------------------------------------

    # @belongs: codegen or init
    def _get_typename_from_type(self, type):
        typename = self._generate_var_def(type, "!tmp")
        typename = typename.replace("!tmp", "")
        # remove the trailing semicolon
        typename = typename[:-1]
        typename = typename.strip()
        return typename
