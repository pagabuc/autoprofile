import ksymextractor
from elftools_wrapper import ElftoolsWrapper
from collections import defaultdict
from custom_types import Global
from os.path import join as joinpath
from os.path import isfile as isfile
import struct
import re
import sys
import mmap

THRESHOLD_KALLSYMS = 2000
THRESHOLD_KSYMTAB  = 2000

def split_ksyms(all_ksyms):
    ksyms = set()
    percpu_ksyms = set()
    for value, name in all_ksyms:
        if value >= 0xffffffff80000000:
            ksyms.add((value, name.replace("SyS_", "sys_")))

        if value <= 0x100000:
            percpu_ksyms.add((value, name))

    return sorted(percpu_ksyms), sorted(ksyms)

class DumpBackend(ElftoolsWrapper):

    def __init__(self, datadir, kdir=""):
        with open(joinpath(datadir, "dump.raw")) as f:
            self.dump = mmap.mmap(f.fileno(), 2**27, access=mmap.ACCESS_READ)
        self.shift = 0

        if isfile(joinpath(datadir, "vmlinux")):
            print("[+] Init EW")
            super().__init__(datadir, abort=False)
            del self.elffile
            del self.vmlinux

        self.dwarf_functions = defaultdict(list)
        self.addr_to_functions = dict()
        self.global_vars_cache = {}

        self.extract_kallsyms()
        self.fix_one_jmp_functions()

    def read_dump_va(self, va, size):
        pa = va - self.shift
        return self.dump[pa: pa+size]

    def extract_kallsyms(self):
        for ksyms, va, pa in ksymextractor.extract_kallsyms(self.dump):
            if len(ksyms) > THRESHOLD_KALLSYMS:
                break
        else:
            print("[-] kallsyms_on_each_symbol not found, aborting!")
            sys.exit(0)

        self.shift = va - pa

        print("[+] Found %d ksyms!" % len(ksyms))

        # for value, name in ksyms:
        #     print("0x%x %s" % (value, name))

        percpu_ksyms, ksyms = split_ksyms(ksyms)

        for (addr, name), (nextaddr, _) in zip(ksyms, ksyms[1:]):
            size = nextaddr - addr
            function = name.split(".")[0]
            content = self.read_dump_va(addr, size)

            self.global_vars_cache[name] = Global(name, addr, size)
            self.dwarf_functions[function].append((addr, content, name))
            self.addr_to_functions[addr] = function

        for (addr, name), (nextaddr, _) in zip(percpu_ksyms, percpu_ksyms[1:]):
            size = nextaddr - addr
            self.global_vars_cache[name] = Global(name, addr, size)

        print("Found %s functions" % len(self.addr_to_functions))

if __name__ == "__main__":
    import sys
    if len(sys.argv[0]) < 2:
        print("Usage: %s dump.raw" % sys.argv[0])
        sys.exit(0)

    DB = DumpBackend(sys.argv[1])
