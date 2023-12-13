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
parser.add_argument(
    "--dir", "-d",
    default=".",
    help="Path to the directory with database files"
)
args = parser.parse_args()

nfsdb_db = os.path.join(args.dir, ".nfsdb.img")
nfsdb_deps_db = os.path.join(args.dir, ".nfsdb.deps.img")

nfsdb = libetrace.nfsdb()
nfsdb.load(nfsdb_db, quiet=True)
nfsdb.load_deps(nfsdb_deps_db, quiet=True)

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

json_vals = list()
json_vals_openrefs = list()
for C in comps:
    e = nfsdb[C]
    if isinstance(e, list) and len(e) == 1:
        e = e[0]
    json_vals.append({
        "directory": e.cwd,
        "command": " ".join(e.argv),
        "file": e.compilation_info.files[0].path,
    })
    json_vals_openrefs.append({
        "directory": e.cwd,
        "command": " ".join(e.argv),
        "file": e.compilation_info.files[0].path,
        "openfiles": sorted(list(e.parent.openpaths_with_children))
    })

compile_commands_path = os.path.join(args.dir, "compile_commands.json")
with open(compile_commands_path, "w") as f:
    json.dump(json_vals, f, indent=4, sort_keys=False)
print(f"Created compilation database file ({compile_commands_path})")

compile_commands_refs_path = os.path.join(
    args.dir, "compile_commands_refs.json"
)
with open(compile_commands_refs_path, "w") as f:
    json.dump(json_vals_openrefs, f, indent=4, sort_keys=False)
print(
    "Created compilation database file with"
    f"open references ({compile_commands_refs_path})"
)

# Generate reverse dependency map file
amdeps = dict()
for m, T in nfsdb.linked_modules():
    amdeps[m.path] = list(set([x.path for x in nfsdb.mdeps(m.path)]))

rdeps: dict[str, set[str]] = {}
for m in amdeps:
    for f in amdeps[m]:
        rdeps.setdefault(f, set())
        rdeps[f].add(m)

rdm = {}
for f in deps:
    if f.endswith(".c") or f.endswith(".h"):
        rdm[f] = list(rdeps[f])
rdm_path = os.path.join(args.dir, "rdm.json")
with open(rdm_path, "w") as f:
    f.write(json.dumps(rdm, indent=4, sort_keys=False))
print(f"Created reverse dependency map file ({rdm_path})")
