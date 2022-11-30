#!/usr/bin/env python3

# Auto off-target PoC
# Copyright Samsung Electronics
# Samsung Mobile Security Team @ Samsung R&D Poland

import logging
import urllib.request
from collections import OrderedDict
import json
import os


class BASconnector:

    def __init__(self, url, product=None, version=None, build_type=None, cache_size=100000, db=None):
        self.url = url + "/"
        if product is not None and version is not None and build_type is not None:
            self.url += "BAS_{}_{}-{}/".format(product, version, build_type)
        logging.info("Will use BAS server under {}".format(self.url))
        self.cache_size = cache_size
        self.cache = OrderedDict()
        self.db = db
        if self.db is not None:
            self.db_index = self.db.create_local_index("BAS", "loc", extra_field_name=None, cache_size=100000)

    def __str__(self):
        return "[BASconnector] for {}".format(self.url)

    def import_data_to_db(self, json_file):
        if self.db is None:
            return

        bas_data = {}
        with open(json_file, "r") as rfile:
            logging.info("Loading JSON to RAM")
            bas_data = json.load(rfile)

        tmp = []
        for entry in bas_data:
            item = {"loc": entry, "entries": bas_data[entry]}
            tmp.append(item)

        self.db.store_many_in_collection("BAS", tmp)
        del tmp
        del bas_data

        self.db_index = self.db.create_local_index("BAS", "loc", extra_field_name=None, cache_size=100000)

    # retrieves the module in which the source file is compiled
    def get_module_for_source_file(self, src_path, location):
        if self.cache_size > 0 and location in self.cache:
            return self.cache[location]

        # we need both location and src_path
        # this is because for functions defined in header file
        # will have location set to the header and source path set
        # to _some_ file that includes that header
        isheader = False
        loc = os.path.abspath(location.split(":")[0])
        if loc[-2:] == ".h":
            isheader = True
        logging.debug("location is {} isheader {}".format(loc, isheader))

        if self.db is None:
            request = "{}/?revdeps_for={}".format(self.url, loc)
            contents = urllib.request.urlopen(request).read().decode('utf-8')
            # the returned contents is a JSON dict - let's use eval to create
            # dict object from a string
            contents = eval(contents)
        else:
            contents = self.db_index[loc]

        if contents is None:
            logging.warning("cannot find {} in rdm database".format(loc))
            return []

        if self.cache_size > 0:
            self.cache[location] = contents["entries"]
            if len(self.cache) > self.cache_size:
                self.cache.popitem(last=False)

        return contents["entries"]
        # max = 0
        # final_entry = ""
        # if isheader == False:
        #     # since in the kernel we have direct and non-direct modules
        #     # returned by BAS, we select the module with the deepest path
        #     for e in contents["entries"]:
        #         count = e.count("/")
        #         if count > max:
        #             max = count
        #             final_entry = e

        # if isheader:
        #     return contents["entries"]
        # else:
        #     return [ final_entry ]
