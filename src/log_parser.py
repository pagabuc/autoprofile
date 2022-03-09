import json
from collections import defaultdict
from os.path import normpath
from os.path import join as joinpath


from location import Location
from utils import normfunc, get_struct
from access import AccessManager
from chain import AccessChain
from record import Record, RecordManager

import logging

l = logging.getLogger('parser')
l.setLevel(logging.DEBUG)

class LogParser:

    def __init__(self, AM, RM, datadir):
        self.AM = AM
        self.RM = RM
        self.datadir = datadir

        self.functions_decl = dict()
        self.compile_unit = defaultdict(list)

        self.ifdefs = defaultdict(set)
        self.randomize_layout_macro = defaultdict(set)
        self.not_uniq_functions = set()
        self.global_arr = set()
        self.global_ptr = set()

        self.targets = []
        self.volatility_targets = []

        self.parse_joern_file()
        self.parse_pptrace_file()
        self.parse_plugin_file()

        self.load_targets()

        self.randomize_layout = set()
        self.load_randomize_layout()

    def dump_chains():
        for function, chains in self.AM.items():
            for chain in chains:
                l.debug("[CHAIN] %s" % chain)

    def create_location(self, filename, function, line):
        location = Location(self.fix_path(filename), function, line)
        if self.access_affected_ifdef(location):
            l.debug("Skipping conditional location: %s" % location)
            return None
        return location

    def get_cu_functions(self, filename):
        return self.compile_unit[filename]

    def get_volatility_targets(self):
        return self.volatility_targets

    def get_targets(self):
        return self.targets

    def load_targets(self):
        for l in open(joinpath(self.datadir, "fields_accessed.txt")):
            target  = l.strip().replace("ACCESS: ", "")
            struct = get_struct(target)
            if struct not in self.RM.records:
                target = "struct " + target

            self.targets.append(target)

        self.volatility_targets = list(self.targets)

    def parse_joern_file(self):
        print("[+] Parsing joern.log")
        filt = ["_32.c", "nommu.c", "/tools/", "slob.c", "slub.c", '.cc']
        counter = defaultdict(list)

        for line in open(joinpath(self.datadir, "joern.log")):
            function, _, filename = line.strip().split("\t")
            if "arch/" in filename and "x86" not in filename:
                continue

            if any(i in filename for i in filt):
                continue

            counter[function].append(filename)

        for f, filenames in counter.items():
            if len(filenames) == 1:
                continue
            if len(filenames) == 2:
                if (filenames[0] == filenames[1] or
                    (filenames[0].endswith(".c") and filenames[1].endswith(".h")) or
                    (filenames[1].endswith(".c") and filenames[0].endswith(".h"))):
                    continue

            self.not_uniq_functions.add(f)

    def fix_path(self, path):
        if "./" in path or ".." in path:
            path = normpath(path)

        if "-allyes" in path:
            path = path[path.index("-allyes")+len("-allyes")+1:]

        return path

    def get_info_from_se(self, s, e):
        filename, start = s.split(":")[:2]
        end = e.split(":")[1]
        return self.fix_path(filename), int(start), int(end)

    def parse_pptrace_line(self, buf):
        e = json.loads(buf)

        if e["Callback"] == "MacroExpands":
            filename, start, end = self.get_info_from_se(*e["Range"])

            if (e["MacroNameTok"] == "__randomize_layout" or
                e["MacroNameTok"] == "randomized_struct_fields_start"):
                self.randomize_layout_macro[filename].add(start)

            # Macros similar to "BUG" are rarely present, so we treat them as ifdefs.
            if ("BUG" in e["MacroNameTok"] or "WARN" in e["MacroNameTok"] or
                "kdebug" == e["MacroNameTok"] or "lockdep" in e["MacroNameTok"] or
                "pr_debug" == e["MacroNameTok"] or "dbg" in e["MacroNameTok"] ):
                self.ifdefs[filename].add((start, end))

        if e["Callback"] == "Endif":
            filename, start, end = self.get_info_from_se(e["IfLoc"], e["Loc"])
            self.ifdefs[filename].add((start, end))

    def parse_pptrace_file(self):
        print("[+] Parsing pptrace.json")

        for line in open(joinpath(self.datadir, "pptrace.json")):
            if "(nonfile)" not in line:
                self.parse_pptrace_line(line)

        for e in self.ifdefs:
            self.ifdefs[e] = list(self.ifdefs[e])
            self.ifdefs[e].sort()

    def create_chain(self, filename, function, access):
        if (access["type"] == "normal" or
            any("anonymous at" in e or "NULL TYPE" in e for e in access["chain"])):
            return None

        location = self.create_location(filename, function, int(access["line"]))
        if location is None:
            return None

        return AccessChain(location, access["type"], access["chain"], access["source"],
                           access["var_id"], int(access.get("ptr2ptr", 0)))

    def process_call(self, filename, caller, call):
        call_location = self.create_location(filename, caller, int(call["line"]))
        if call_location is None:
            return None

        callee = call["callee"]
        self.AM.calls[filename, caller][call_location, callee] = []

        for arg in call.get("args", []):
            ac = self.create_chain(filename, caller, arg)
            if ac is not None and ac.source != callee:
                position = int(arg["position"])
                self.AM.calls[filename, caller][call_location, callee].append((position, ac))
                l.debug("[PARAM] %s %s %s" % (callee, position, ac))

            # If this is not only a single variable, but contains also a chain:
            if ac is not None and ac.chain:
                self.AM.chains[filename, caller].add(ac)

    def process_function_calls(self, filename, function, calls):
        for call in calls:
            self.process_call(filename, function, call)

    def process_function_accesses(self, filename, function, accesses):
        for access in accesses:
            ac = self.create_chain(filename, function, access)
            if ac is not None:
                self.AM.chains[filename, function].add(ac)

    def process_function_returns(self, filename, function, returns):
        for ret in returns:
            ac = self.create_chain(filename, function, ret)
            if ac is not None:
                l.debug("[RET] %s returns %s" % (function, ac))
                self.AM.chains[filename, function].add(ac)
                self.AM.returns[filename, function].add(ac)

    def load_randomize_layout(self):
        for struct, record in self.RM.records.items():
            for macro in self.randomize_layout_macro[record.filename]:
                if record.start <= macro <= record.end:
                    self.randomize_layout.add(struct)

        del self.randomize_layout_macro

    def process_function_decl(self, e, filename):
        if any(i in filename for i in ["fs/btrfs", "btrfs.h", "drivers/staging", "kasan"]):
            return

        function = normfunc(e["name"])
        start = int(e["start"])
        end = int(e["end"])

        self.AM.ffmap[function].add(filename)
        self.functions_decl[(filename, function)] = (start, end)
        self.compile_unit[filename].append(function)

        self.process_function_accesses(filename, function, e.get("accesses", []))
        self.process_function_calls(filename, function, e.get("calls", []))
        self.process_function_returns(filename, function, e.get("returns", []))

    def process_global_arr(self, e):
        self.global_arr.add(e["name"])

    def process_global_ptr(self, e):
        self.global_ptr.add(e["name"])

    def process_record(self, e, filename):
        assert("body" in e)
        self.RM.add_record(filename, e["struct_type"], int(e["start"]), int(e["end"]), e["body"])
        l.debug("DD: %s" % e["struct_type"])
        record = self.RM.get_record(e["struct_type"])
        record.ifdefs = dict([(f[0], self.field_affected_ifdef(record, f[0])) for f in record.body])
        l.debug("CCC: %s %s" % (record.name, record.ifdefs))

    def parse_plugin_file(self):
        print("[+] Parsing plugin.json")
        jsons = []
        for line in open(joinpath(self.datadir, "plugin.json")):
            e = json.loads(line)
            filename = self.fix_path(e.get("filename", ""))
            if filename and (filename.startswith("scripts/") or filename.startswith("tools/")):
                continue

            if e["type"] == "FUNCTION_DECL":
                self.process_function_decl(e, filename)
            if e["type"] == "RECORD":
                self.process_record(e, filename)
            elif e["type"] == "GLOBAL_ARR":
                self.process_global_arr(e)
            elif e["type"] == "GLOBAL_PTR":
                self.process_global_ptr(e)

    def is_target_randomized(self, target):
        return get_struct(target) in self.randomize_layout

    def is_function_uniq(self, function):
        return function not in self.not_uniq_functions

    # If the ifdef is contained in this structure and comes before our field..
    def field_affected_ifdef(self, record, field):
        if field not in record.lines:
            return True

        field_line = record.lines[field]
        for start_if, end_if in self.ifdefs[record.filename]:
            if (record.start <= start_if <= end_if <= record.end) and start_if < field_line:
                return True

        return False

    # Accesses that are contained in a ifdef but not the whole function is contained.
    def access_affected_ifdef(self, loc):
        start_f, end_f = self.functions_decl[(loc.filename, loc.function)]
        for start_if, end_if in self.ifdefs[loc.filename]:
            if start_if <= loc.line <= end_if and not (start_if <= start_f <= end_f <= end_if):
                return True
        return False

    def find_new_targets_chain(self, chain, targets):
        for t in chain:
            if t in targets:
                i = chain.position(t)
                yield from chain[:i]
                while chain.is_dot(i):
                    yield chain[i]
                    i+=1

    def get_surrounding_fields(self, t, n=3):
        struct, field = t.split("->")
        body = [b[0] for b in self.RM.records[struct].body]
        i = body.index(field)
        start = max(i-n, 0)
        end = min(i+n, len(body)-1)
        new_fields = body[start: end+1]
        for nf in new_fields:
            if nf != field:
                yield "%s->%s" % (struct, nf)

    def append_new_targets(self):
        print("[+] Searching for new targets contained in chains where our targets are as well..")
        new_targets = set()
        for t in self.volatility_targets:
            try:
                for nt in self.get_surrounding_fields(t):
                    new_targets.add(nt)
            except:
                continue

        targets = new_targets | set(self.volatility_targets)
        for chains in self.AM.accesses.values():
            for chain in chains:
                for t in self.find_new_targets_chain(chain, targets):
                    new_targets.add(t)

        for nt in new_targets:
            l.debug("NEW TARGET: %s" % nt)

        print("Loaded %d new targets" % len(new_targets))

        self.targets += new_targets
        self.targets = list(set(self.targets))

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print('Usage: %s datadir' % sys.argv[0])
        sys.exit(-1)

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    l = logging.getLogger('parser')
    l.setLevel(logging.DEBUG)
    LP = LogParser(AccessManager(), RecordManager(), sys.argv[1])
