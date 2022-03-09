from capstone import *
from capstone.x86 import *
import struct


# 1129:	48 c7 c0 80 14 21 82          	mov    $0xffffffff82211480,%rax
# 1130:	48 c7 c3 80 14 21 82          	mov    $0xffffffff82211480,%rbx
# 1137:	48 c7 c1 80 14 21 82          	mov    $0xffffffff82211480,%rcx
# 113e:	48 c7 c2 80 14 21 82          	mov    $0xffffffff82211480,%rdx
# 1145:	48 c7 c5 80 14 21 82          	mov    $0xffffffff82211480,%rbp
# 114c:	48 c7 c6 80 14 21 82          	mov    $0xffffffff82211480,%rsi
# 1153:	48 c7 c7 80 14 21 82          	mov    $0xffffffff82211480,%rdi
# 115a:	49 c7 c0 80 14 21 82          	mov    $0xffffffff82211480,%r8
# 1161:	49 c7 c1 80 14 21 82          	mov    $0xffffffff82211480,%r9
# 1168:	49 c7 c2 80 14 21 82          	mov    $0xffffffff82211480,%r10
# 116f:	49 c7 c3 80 14 21 82          	mov    $0xffffffff82211480,%r11
# 1176:	49 c7 c4 80 14 21 82          	mov    $0xffffffff82211480,%r12
# 117d:	49 c7 c5 80 14 21 82          	mov    $0xffffffff82211480,%r13
# 1184:	49 c7 c6 80 14 21 82          	mov    $0xffffffff82211480,%r14
# 118b:	49 c7 c7 80 14 21 82          	mov    $0xffffffff82211480,%r15

table = { X86_REG_RAX: b"\x48\xc7\xc0",
          X86_REG_RBX: b"\x48\xc7\xc3",
          X86_REG_RCX: b"\x48\xc7\xc1",
          X86_REG_RDX: b"\x48\xc7\xc2",
          X86_REG_RBP: b"\x48\xc7\xc5",
          X86_REG_RSI: b"\x48\xc7\xc6",
          X86_REG_RDI: b"\x48\xc7\xc7",
          X86_REG_R8:  b"\x49\xc7\xc0",
          X86_REG_R9:  b"\x49\xc7\xc1",
          X86_REG_R10: b"\x49\xc7\xc2",
          X86_REG_R11: b"\x49\xc7\xc3",
          X86_REG_R12: b"\x49\xc7\xc4",
          X86_REG_R13: b"\x49\xc7\xc5",
          X86_REG_R14: b"\x49\xc7\xc6",
          X86_REG_R15: b"\x49\xc7\xc7"}

# 1129:       48 8b 04 25 c0 02 02 00         mov    0x202c0,%rax
# 1131:       48 8b 1c 25 c0 02 02 00         mov    0x202c0,%rbx
# 1141:       48 8b 0c 25 c0 02 02 00         mov    0x202c0,%rcx
# 1149:       48 8b 14 25 c0 02 02 00         mov    0x202c0,%rdx
# 1151:       48 8b 2c 25 c0 02 02 00         mov    0x202c0,%rbp
# 1159:       48 8b 34 25 c0 02 02 00         mov    0x202c0,%rsi
# 1161:       48 8b 3c 25 c0 02 02 00         mov    0x202c0,%rdi
# 1169:       4c 8b 04 25 c0 02 02 00         mov    0x202c0,%r8
# 1171:       4c 8b 0c 25 c0 02 02 00         mov    0x202c0,%r9
# 1179:       4c 8b 14 25 c0 02 02 00         mov    0x202c0,%r10
# 1181:       4c 8b 1c 25 c0 02 02 00         mov    0x202c0,%r11
# 1189:       4c 8b 24 25 c0 02 02 00         mov    0x202c0,%r12
# 1191:       4c 8b 2c 25 c0 02 02 00         mov    0x202c0,%r13
# 1199:       4c 8b 34 25 c0 02 02 00         mov    0x202c0,%r14
# 11a1:       4c 8b 3c 25 c0 02 02 00         mov    0x202c0,%r15

table2 = { X86_REG_RAX: b"\x48\x8b\x04\x25",
           X86_REG_RBX: b"\x48\x8b\x1c\x25",
           X86_REG_RCX: b"\x48\x8b\x0c\x25",
           X86_REG_RDX: b"\x48\x8b\x14\x25",
           X86_REG_RBP: b"\x48\x8b\x2c\x25",
           X86_REG_RSI: b"\x48\x8b\x34\x25",
           X86_REG_RDI: b"\x48\x8b\x3c\x25",
           X86_REG_R8:  b"\x4c\x8b\x04\x25",
           X86_REG_R9:  b"\x4c\x8b\x0c\x25",
           X86_REG_R10: b"\x4c\x8b\x14\x25",
           X86_REG_R11: b"\x4c\x8b\x1c\x25",
           X86_REG_R12: b"\x4c\x8b\x24\x25",
           X86_REG_R13: b"\x4c\x8b\x2c\x25",
           X86_REG_R14: b"\x4c\x8b\x34\x25",
           X86_REG_R15: b"\x4c\x8b\x3c\x25"}

class Function:
    def __init__(self, name, load_va, entry_va, code, size, parts):
        self.name = name
        self.load_va = load_va
        self.entry_va = entry_va
        self.code = code
        self.size = size
        self.parts = parts # A list of (va, len(code))
        
        self.clean_function()
        
    def __repr__(self):
        return "0x%x:%s:%d" % (self.load_va, self.name, self.size)
    
    def __hash__(self):
         return hash(self.load_va)
     
    def __eq__(self, other):
        return self.load_va == other.load_va

    def va_in_function(self, va):
        return any(pva <= va < pva+plen for pva, plen in self.parts)
    
    def disasm_function(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        for i in md.disasm(self.code, self.load_va):
            yield i

    def print_function(self):
        for i in self.disasm_function():
            if i.mnemonic != "hlt":
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    def transform_movgs(self, off, addr):
        for i in self.disasm_function():

            if i.id == X86_INS_MOV and i.operands[1].reg == X86_REG_GS and i.operands[1].mem.disp == off:
                r = i.operands[0].reg
                if r not in table:
                    return                
                new_insn = table[r] + struct.pack("<I", addr & 0xffffffff)
                p = new_insn + b"\x90" * (i.size - len(new_insn))
                self.patch(i.address, p)

    # mov    rbx,QWORD PTR gs:[rip+0x7efcefaf] 
    def transform_movgs_percpu(self, addr):
        for i in self.disasm_function():
            
            if i.id == X86_INS_MOV and i.operands[1].reg == X86_REG_GS and i.operands[1].mem.base == X86_REG_RIP:
                
                disp = (i.address + i.size + i.operands[1].mem.disp) & 0xffffffffffffffff 
                if disp != addr:
                    continue
                r = i.operands[0].reg
                if r not in table:
                    return           
                new_insn = table2[r] + struct.pack("<I", addr & 0xffffffff)
                p = new_insn + b"\x90" * (i.size - len(new_insn))
                self.patch(i.address, p)
                
        
    def patch(self, va, p):
        offset = va - self.load_va
        self.code = self.code[:offset] + p + self.code[offset+len(p):]
        
    def clean_function(self):
        for i in self.disasm_function():
            
            # ud2 are skipped by angr, while hlt correctly stop the execution
            if i.id == X86_INS_UD2:
                self.patch(i.address, b"\xf4"*i.size)
                
            # Here we miss handling for "rdpkru", once capstone implements it..
            if (any(p in [X86_PREFIX_REP, X86_PREFIX_REPE, X86_PREFIX_REPNE] for p in i.prefix) or
                any(o.reg in [X86_REG_CR4, X86_REG_CR3, X86_REG_FS, X86_REG_DS, X86_REG_ES] for o in i.operands if o.type == X86_OP_REG) or
                (i.id == X86_INS_CALL and (i.operands[0].type == X86_OP_MEM or i.operands[0].type == X86_OP_REG)) or
                i.id in [X86_INS_WRMSR, X86_INS_RDMSR, X86_INS_LTR]):
                self.patch(i.address, b"\x90"*i.size)

            if i.id == X86_INS_JMP:
                target = ctypes.c_uint64(i.operands[0].imm).value
                if not self.va_in_function(target):
                    self.patch(i.address, b"\x90"*i.size)
                
    def get_called_funcs(self):
        called_funcs = []
        for i in self.disasm_function():        
            if i.mnemonic == "call":
                va = ctypes.c_uint64(i.operands[0].imm).value
                called_funcs.append(va)
        return called_funcs

    def has_call_to(self, F2):
        return any(F2.va_in_function(va) for va in self.get_called_funcs())
    
    def calls_any(self, function_list):
        for F2 in function_list:
            if F2 and self.has_call_to(F2):
                return True
        return False

class Global:
    def __init__(self, name, va, size):
        self.name = name
        self.va = va
        self.size = size

    def __repr__(self):
        return "0x%x:%s:%d" % (self.va, self.name, self.size)

    def __hash__(self):
         return hash(self.va)
     
    def __eq__(self, other):
        return self.va == other.va
