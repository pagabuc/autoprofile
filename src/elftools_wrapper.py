from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection
from elftools.elf.constants import SH_FLAGS
from elftools.dwarf.ranges import RangeEntry, BaseAddressEntry
from utils import md5_f
import os
import sys
import pickle
import resource
from collections import defaultdict
from os.path import normpath as normpath
from os.path import abspath as abspath
import struct
from custom_types import *
from capstone import *
from capstone.x86 import *
import elftools

import logging
l = logging.getLogger('elftools')

# XXX We should create Function object in the load_functions methods..

class ElftoolsWrapper:
    def __init__(self, datadir, abort=True):
        self.vmlinux_path = abspath('%s/vmlinux' % datadir)
        self.vmlinux = open(self.vmlinux_path, "rb")
        self.elffile = ELFFile(self.vmlinux)

        if not self.elffile.has_dwarf_info() and abort:
            print('[-] %s has no DWARF info, aborting.' % self.vmlinux_path)
            sys.exit(0)

        # Keys are functions name, splitted at '.'. Values are (address, content, original_name)
        self.dwarf_functions = defaultdict(list)
        self.addr_to_functions = dict()
        self.global_vars_cache = {}

        self.structs = defaultdict(dict)

        self.load_functions()
        self.load_structs()
        self.populate_global_vars_cache()

        self.functions_cache = {}
        # for s in self.structs:
        #     for f in self.structs[s]:
        #         l.debug("%s->%s = %d" % (s,f,self.structs[s][f]))

    def get_functions_names(self):
        return set(self.dwarf_functions.keys())

    ### Dwarf parsing
    def get_member_loc(self, field):
        try:
            v = field.attributes["DW_AT_data_member_location"].value
            if type(v) == elftools.construct.lib.container.ListContainer:
                    v = v[1]
            return v
        except KeyError:
            return None

    def get_name(self, field):
        return field.attributes["DW_AT_name"].value.decode()

    def handle_struct(self, child, anons, CU, off=0):
        childs = list(child.iter_children())
        for field in childs:
            tag = field.tag
            data = field.attributes

            # unnamed field (DW_TAG_member without name - we retreive its definition from anons)
            if tag == "DW_TAG_member" and "DW_AT_name" not in data:
                type_offset = CU.cu_offset + data["DW_AT_type"].value
                if type_offset not in anons:
                    continue

                rec_off = self.get_member_loc(field)
                if rec_off == None:
                    rec_off = off

                for x in self.handle_struct(anons[type_offset], anons, CU, rec_off):
                    yield x

            # Before any _named_ inner struct/union there's a
            # DW_TAG_MEMBER, from where we take the offset of the
            # struct/union
            if tag == "DW_TAG_structure_type" or tag == "DW_TAG_union_type":
                rec_off = self.get_member_loc(childs[i-1])
                field_name = self.get_name(field)
                yield field_name, rec_off
                # for x in self.handle_struct(field, anons, CU, rec_off):
                #     yield x

            # Otherwise is a normal field (DW_TAG_member with name)
            elif tag == "DW_TAG_member" and "DW_AT_name" in data:
                field_name = self.get_name(field)

                # Bit fields handling taken from volatility/dwarf.py
                if 'DW_AT_data_member_location' not in data:
                    field_offs = 0
                elif 'DW_AT_bit_size' in data and 'DW_AT_bit_offset' in data:
                    full_size = int(data['DW_AT_byte_size'].value) * 8
                    stbit = int(data['DW_AT_bit_offset'].value)
                    edbit = stbit + int(data['DW_AT_bit_size'].value)
                    stbit = full_size - stbit
                    edbit = full_size - edbit
                    stbit, edbit = edbit, stbit
                    field_offs = self.get_member_loc(field) + (stbit / 8)
                else:
                    field_offs = self.get_member_loc(field)

                try:
                    yield field_name, field_offs + off
                except:
                    pass

    def is_anon_union_or_struct(self, c):
        return ((c.tag == "DW_TAG_structure_type" and "DW_AT_name" not in c.attributes) or
                c.tag == "DW_TAG_union_type")

    def handle_CU(self, CU):
        top_DIE = CU.get_top_DIE()
        
        anons = dict()
        for child in top_DIE.iter_children():
            if self.is_anon_union_or_struct(child):
                anons[child.offset] = child
            
        for child in top_DIE.iter_children():
            tag = child.tag
            data = child.attributes
            
            # untyped global variables
            if tag == "DW_TAG_variable" and "DW_AT_type" in data:
                type_offset = CU.cu_offset + data["DW_AT_type"].value
                try:
                    child = anons[type_offset]
                    struct_name = "struct ANON_%s" % data["DW_AT_name"].value.decode()
                except KeyError:
                    continue

                for field_name, field_offs in self.handle_struct(child, anons, CU):
                    self.structs[struct_name][field_name] = field_offs

            elif tag == "DW_TAG_structure_type" and child.has_children:
                try:
                    struct_name = "struct %s" % data["DW_AT_name"].value.decode()
                except KeyError:
                    continue

                if struct_name in self.structs:
                    continue

                for field_name, field_offs in self.handle_struct(child, anons, CU):
                    self.structs[struct_name][field_name] = field_offs
                    
            elif tag == "DW_TAG_typedef" and "DW_AT_type" in data:
                type_offset = CU.cu_offset + data["DW_AT_type"].value
                try:
                    child = anons[type_offset]
                    struct_name = "%s" % data["DW_AT_name"].value.decode()
                except KeyError:
                    continue
                
                for field_name, field_offs in self.handle_struct(child, anons, CU):
                    self.structs[struct_name][field_name] = field_offs
                
                
    def load_structs(self):
        structs_file = "/tmp/%s.structs.pickle" % md5_f(self.vmlinux_path)
        if os.path.isfile(structs_file):
            l.info("[~] Loading cached structs info from %s" % (structs_file))
            with open(structs_file, 'rb') as f:
                self.structs = pickle.load(f)
            return

        l.info("[~] Cached structs info not present, generating them from: %s" % self.vmlinux_path)
        dwarfinfo = self.elffile.get_dwarf_info()
        range_lists = dwarfinfo.range_lists()
        for CU in dwarfinfo.iter_CUs():
            self.handle_CU(CU)

        pickle.dump(self.structs, open(structs_file,"wb"))

    def list_symbols(self):
        for section in self.elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    yield symbol

    def get_jump_target(self, addr, code):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        insts =  [i for i in md.disasm(code, addr) if i.mnemonic != "nop"]
        if len(insts) == 1:
            i = insts[0]
            if i.mnemonic == 'jmp':
                return ctypes.c_uint64(i.operands[0].imm).value

        raise KeyError

    def load_functions(self):
        sections = [s for s in self.elffile.iter_sections()]
        tmp_functions = defaultdict(list)
        for symbol in self.list_symbols():
            # XXX: rewind_stack_do_exit is a function but has STT_NOTYPE
            if symbol.entry["st_info"]["type"] == 'STT_OBJECT':
                continue

            st_shndx = symbol.entry["st_shndx"]
            if st_shndx in ["SHN_UNDEF", "SHN_ABS"]:
                continue

            section = sections[st_shndx]

            sh_addr = section.header["sh_addr"]
            sh_offset = section.header["sh_offset"]
            symbol_addr = symbol.entry["st_value"]
            symbol_size = symbol.entry["st_size"]

            # e.g. __init_begin
            if not sh_addr or symbol_size == 0:
                continue

            file_offset = symbol_addr - sh_addr + sh_offset
            symbol_content = self.read_from_file(file_offset, symbol_size)
            function = symbol.name.split(".")[0]
            self.dwarf_functions[function].append((symbol_addr, symbol_content, symbol.name))
            self.addr_to_functions[symbol_addr] = function
            
        self.fix_one_jmp_functions()

    # There are some syscall handlers that contains only a jump to a SYSC_function.
    # Here we find these cases and replace the entries of the interested functions with the jump target.            
    def fix_one_jmp_functions(self):
        for f in self.dwarf_functions:
            for (addr, content, name) in self.dwarf_functions[f]:
                if len(content) > 32:
                    continue
                try:
                    target = self.get_jump_target(addr, content)
                    new_function = self.addr_to_functions[target]
                    self.dwarf_functions[f] = self.dwarf_functions[new_function]
                except KeyError:
                    continue

    def populate_global_vars_cache(self):
        for symbol in self.list_symbols():
            if symbol.entry["st_info"]["type"] == 'STT_OBJECT':
                self.global_vars_cache[symbol.name] = Global(symbol.name,
                                                             symbol.entry["st_value"],
                                                             symbol.entry["st_size"])

    def get_global_var(self, global_var_name):
        try:
            return self.global_vars_cache[global_var_name]
        except KeyError:
            return None

    # Returns the name of the two functions surroding va
    def get_surronding_funcs(self, va):
        vas = sorted(list(self.addr_to_functions.keys()))
        i = vas.index(va)
        l = r = ""
        if i > 0:
            l = self.addr_to_functions[vas[i-1]]
        if i < len(vas) -1:
            r = self.addr_to_functions[vas[i+1]]
        return l, r

    # note: cu_funcs are uniq functions.
    def _get_function(self, function, cu_funcs):
        chunks = []
        entry_va = 0

        candidates = 0
        skip_vas = []

        if cu_funcs != None:
            for vaddr, _, orig_name in self.dwarf_functions[function]:
                left, right = self.get_surronding_funcs(vaddr)
                if left not in cu_funcs or right not in cu_funcs:
                    # If we have a function "foo.cold" and foo is not
                    # uniq, we don't skip "foo.cold" when finding the
                    # chunks related to foo, because we don't know to
                    # which function "foo" they belong.  To stay on
                    # the safe side we glue everything since parts not
                    # belonging to the correct one will not be executed.
                    # XXX actually we could, because .cold functions are close to the original ones.

                    if orig_name != function and not orig_name.startswith("%s." % function):
                        skip_vas.append(vaddr)
                else:
                    candidates +=1

            if candidates != 1:
                l.debug("elftools_wrapper cannot find the uniq function: %s" % function)
                raise KeyError

        for name in self.dwarf_functions:
            for (vaddr, content, orig_name) in self.dwarf_functions[name]:
                if vaddr in skip_vas:
                    continue

                if name != function:
                    continue

                if '.isra' in orig_name:
                    raise KeyError

                chunks.append((vaddr, content, orig_name))
                if not orig_name.startswith("%s." % function):
                    entry_va = vaddr

        if len(chunks) == 0:
            raise KeyError

        if entry_va == 0:
            # If all chunks are 'foo.part', 'foo.part.cold' then we
            # take as entry_va the address of the shortest named
            # function.
            if all(c[2].startswith("%s." % function) for c in chunks):
                chunks.sort(key=lambda x: len(x[2]))
                entry_va = chunks[0][0]
            else:
                l.error("[-] _get_function can't find the entry_va for %s" % function)
                raise KeyError

        max_addr = max([c[0] for c in chunks])
        min_addr = min([c[0] for c in chunks])

        if (max_addr - min_addr) > 0x4000:
            l.error("[-] Function %s is too big %d " % (function, max_addr - min_addr))
            raise KeyError

        code = self.join_chunks(chunks)
        
        if all(c == 0 for c in code):
            l.error("Function %s is all zeroes!" % function)
            raise KeyError

        
        if code == b"\x0f\x0b": #  UD2
            raise KeyError

        if code.startswith(b"\x0f\x0b") or code.startswith(b"\xf4"):
            l.error("UD2/HLT function %s" % code)
            
        size = sum([len(p[1]) for p in chunks])
        load_va = sorted(chunks)[0][0]
        parts = [(va, len(code)) for va, code, _ in chunks]
        return Function(function, load_va, entry_va, code, size, parts)

    def get_function(self, function, cu_funcs=None, parts_only=False):
        if cu_funcs is None:
            key = (function, cu_funcs, parts_only)
        else:
            key = (function, tuple(cu_funcs), parts_only)

        try:
            return self.functions_cache[key]
        except KeyError:
            pass

        try:
            if parts_only:
                parts = [(vaddr, len(code)) for vaddr, code, _ in self.dwarf_functions[function]]
                F = Function(function, 0, 0, b"", 0, parts)
            else:
                F = self._get_function(function, cu_funcs)
        except KeyError:
            F = None

        self.functions_cache[key] = F

        return F

    def get_offset_target(self, target):
        try:
            struct, field = target.split("->")
            return self.structs[struct][field]
        except (KeyError, ValueError) as e:
            return -1

    def join_chunks(self, chunks):
        res = b""
        chunks.sort()

        for (start_addr, content, _),(next_addr, _, _) in zip(chunks, chunks[1:]):
            res += content.ljust(next_addr - start_addr, b'\xf4')
        res+= chunks[-1][1]

        return res

    def read_from_file(self, offset, size):
        self.vmlinux.seek(offset)
        return self.vmlinux.read(size)

    # def __del__(self):
    #     self.vmlinux.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s kdir" % sys.argv[0])
        sys.exit(-1)

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    EW = ElftoolsWrapper(sys.argv[1])
