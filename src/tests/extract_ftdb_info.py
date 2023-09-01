#! /bin/python3

# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import libetrace
import json
import os
import argparse

parser = argparse.ArgumentParser(description="Generate files needed for AoT")
parser.add_argument("--dir", "-d", default=".", help="Path to the directory with database files")
args = parser.parse_args()

nfsdb_db = os.path.join(args.dir, ".nfsdb.img")
nfsdb_deps_db = os.path.join(args.dir, ".nfsdb.deps.img")

nfsdb = libetrace.nfsdb()
nfsdb.load(nfsdb_db, quiet=True, mp_safe=True)
nfsdb.load_deps(nfsdb_deps_db, quiet=True, mp_safe=True)

L = nfsdb.linked_modules()
print(f"Number of modules: {len(L)}")

mdeps = dict()
for m in L:
    mdeps[m[0].path] = list(set([x.path for x in nfsdb.mdeps(m[0].path)]))
deps = set()
for x in mdeps.values():
    deps |= set(x)
print(f"Total dependencies: {len(deps)}")

cmap = {}
for e in nfsdb.filtered_execs_iter(has_comp_info=True):
    for cf in e.compilation_info.files:
        if cf.path not in cmap:
            cmap[cf.path] = e

comps = set()
for f in deps:
    if f in cmap:
        comps.add((cmap[f].eid.pid, cmap[f].eid.index))
print(f"Number of compilations: {len(comps)}")


# Generate compilation database
def json_command(cmd):
    return json.dumps(" ".join([x.rstrip()
                                .replace("\\", "\\\\")
                                .replace("\"", "\\\"")
                                .replace(" ", "\\ ") for x in cmd]))


json_vals = list()
json_vals_openrefs = list()
for C in comps:
    e = nfsdb[C]
    if isinstance(e, list) and len(e) == 1:
        e = e[0]
    dir = json.dumps(e.cwd)
    command = json_command(e.argv)
    file = json.dumps(e.compilation_info.files[0].path)
    json_vals.append("{\"directory\":%s,\"command\":%s,\"file\":%s}" % (dir, command, file))
    openfiles = json.dumps(sorted([o for o in e.parent.openpaths_with_children]))
    json_vals_openrefs.append("{\"directory\":%s,\"command\":%s,\"file\":%s,\"openfiles\":%s}" % (dir, command, file, openfiles))

compile_commands_path = os.path.join(args.dir, "compile_commands.json")
with open(compile_commands_path, "w") as f:
    f.write(json.dumps(json.loads("[%s]" % ",".join(json_vals)), indent=4, sort_keys=False))
print(f"Created compilation database file ({compile_commands_path})")

compile_commands_refs_path = os.path.join(args.dir, "compile_commands_refs.json")
with open(compile_commands_refs_path, "w") as f:
    f.write(json.dumps(json.loads("[%s]" % ",".join(json_vals_openrefs)), indent=4, sort_keys=False))
print(f"Created compilation database file with open references ({compile_commands_refs_path})")

# Generate reverse dependency map file
amdeps = dict()
for m, T in nfsdb.linked_modules():
    amdeps[m.path] = list(set([x.path for x in nfsdb.mdeps(m.path)]))
rdeps = {}
for m in amdeps:
    for f in amdeps[m]:
        if f in rdeps:
            rdeps[f].add(m)
        else:
            rdeps[f] = set([m])

rdm = {}
for f in deps:
    if f.endswith(".c") or f.endswith(".h"):
        rdm[f] = list(rdeps[f])
rdm_path = os.path.join(args.dir, "rdm.json")
with open(rdm_path, "w") as f:
    f.write(json.dumps(rdm, indent=4, sort_keys=False))
print(f"Created reverse dependency map file ({rdm_path})")
