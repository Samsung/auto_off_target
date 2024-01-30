# Auto off-target PoC
###
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

try:
    import libftdb
except ImportError as e:
    print(f"Unable to import libftdb: {e}")


def wrap_libftdb_error(func):
    def wrapped(val):
        try:
            return func(val)
        except libftdb.FtdbError:
            return None

    return wrapped


def create_indices(db):
    def func_by_name(name):
        return db.funcs.entry_by_name(name)

    def func_by_id(id):
        return db.funcs.entry_by_id(id)

    def func_by_hash(hash):
        return db.funcs.entry_by_hash(hash)

    def funcdecl_by_name(name):
        return db.funcdecls.entry_by_name(name)

    def funcdecl_by_id(id):
        return db.funcdecls.entry_by_id(id)

    def funcdecl_by_hash(hash):
        return db.funcdecls.entry_by_hash(hash)

    def global_by_name(name):
        return db.globals.entry_by_name(name)

    def global_by_id(id):
        return db.globals.entry_by_id(id)

    def global_by_hash(hash):
        return db.globals.entry_by_hash(hash)

    def type_by_id(id):
        return db.types.entry_by_id(id)

    def type_by_hash(hash):
        return db.types.entry_by_hash(hash)

    # libftdb constructs a brand new list every time
    # we call db.source_info, this is to avoid doing that
    source_info = db.source_info

    def source_info_by_id(id):
        if id < len(source_info):
            return source_info[id]
        else:
            return None

    bas_cache = dict()
    for bas_entry in db.BAS:
        bas_cache[bas_entry["loc"]] = bas_entry

    def bas_by_loc(loc):
        return bas_cache.get(loc)

    return {
        "funcs": {
            "name": wrap_libftdb_error(func_by_name),
            "id": wrap_libftdb_error(func_by_id),
            "hash": wrap_libftdb_error(func_by_hash),
        },
        "funcdecls": {
            "name": wrap_libftdb_error(funcdecl_by_name),
            "id": wrap_libftdb_error(funcdecl_by_id),
            "hash": wrap_libftdb_error(funcdecl_by_hash),
        },
        "globals": {
            "name": wrap_libftdb_error(global_by_name),
            "id": wrap_libftdb_error(global_by_id),
            "hash": wrap_libftdb_error(global_by_hash),
        },
        "types": {
            "id": wrap_libftdb_error(type_by_id),
            "hash": wrap_libftdb_error(type_by_hash),
        },
        "source_info": {
            "id": source_info_by_id,
        },
        "BAS": {
            "loc": bas_by_loc,
        },
    }
