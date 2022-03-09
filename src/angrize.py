
import angr
import claripy
import logging
import sys
import traceback
import ctypes
import sys
sys.path.append("../src")
from elftools_wrapper import Function
from io import BytesIO

logging.root.handlers.pop()
angr.loggers.setall(logging.ERROR)

l = logging.getLogger('angrize')

state_options = {'LAZY_SOLVES', 'CONSERVATIVE_READ_STRATEGY', 'CONSERVATIVE_WRITE_STRATEGY',
                 'DOWNSIZE_Z3', 'TRACK_MEMORY_ACTIONS'}

# 'TRACK_REGISTER_ACTIONS'

# Some helper functions
def get_rip(state):
    return state.solver.eval(state.regs.rip)

def contains(node, target):
    if type(node) == int:
        return False

    if node.op == 'Extract':
        return False

    if node.op == 'If':
        for a in node.args:
            # cmovne: we check only the branch which contains a BVS equals to target
            return any(contains(a, target) for a in node.args if a.op == 'BVS' and (a == target).is_true())

    if node.op == 'BVS':
        if (node == target).is_true():
            return True
        else:
            raise KeyError()

    return any(contains(a, target) for a in node.args)

def safe_eval(state, expr):
    try:
        return state.solver.eval(expr)
    except:
        return None

def is_general_purpose(state, reg_offset):
    for r in state.arch.register_list:
        if r.general_purpose and r.name != "rip" and r.vex_offset == reg_offset:
            return True
    return False

def get_last_action(state, type, action):
    recent_actions = list(state.history.recent_actions)
    for last_action in recent_actions[::-1]:
        if last_action.ins_addr != state.addr:
            continue
        if last_action.type == "reg" and not is_general_purpose(state, last_action.offset):
            continue
        if last_action.type == type and last_action.action == action:
            return last_action
    return None

def reg_store(state, reg, expr):
    state.registers.store(reg, expr, disable_actions=True, inspect=False)

class Angrize():

    def __init__(self, F, dep, disp, cof, arr, align):
        # Empty the claripy cache to not run out of memory.
        claripy.ast.bv._bvv_cache.clear()
        claripy.ast.bv.BV._hash_cache.clear()

        self.offsets = []
        self.dep = dep
        self.disp = disp
        self.align = align
        self.cof = cof
        self.arr = arr
        self.debug = False

        main_opts = {'backend': 'blob', 'arch': 'x86_64', 'entry_point': 0, 'base_addr': F.load_va}

        self.proj = angr.Project(BytesIO(F.code), support_selfmodifying_code=True,
                                 translation_cache=False, main_opts=main_opts)

        self.init_state = self.proj.factory.call_state(addr=F.entry_va, add_options=state_options)

        self.simgr = self.proj.factory.simgr(self.init_state, save_unsat=True)
        self.simgr.use_technique(angr.exploration_techniques.Coverage(4))

        self.tainted_ptrs = [self.init_state.solver.BVS("ptr_%d" % i, 64) for i in range(len(dep)+1)]
        self.register_bp('address_concretization', angr.BP_AFTER, self.inspect_address_concr)
        self.register_bp('reg_write', angr.BP_AFTER, self.inspect_reg_write)
        self.register_bp('mem_read', angr.BP_AFTER, self.inspect_mem_read)
        self.register_bp('exit', angr.BP_BEFORE, self.handle_exit)
        # self.register_bp('instruction', angr.BP_BEFORE, self.test_instruction)

    def tainted_ptrs_index(self, tp):
        for i, t in enumerate(self.tainted_ptrs):
            if (t == tp).is_true():
                return i
        return -1

    def register_bp(self, what, when, action):
        self.init_state.inspect.b(what, when=when, action=action)

    def explore(self):
        try:
            self.simgr.explore()
        except (RecursionError, ctypes.ArgumentError):
            traceback.print_exc()
            return ["EXCEPTION"]

        if self.cof and self.disp > 0:
            disps = [o + self.disp for o in self.offsets if o + self.disp >= 0]
            self.offsets = disps

        elif self.disp > 0:
            disps = [o - self.disp for o in self.offsets if o - self.disp >= 0]
            self.offsets = disps

        self.offsets = set([abs(o) for o in self.offsets])

        return sorted(self.offsets)

    def test_instruction(self, state):
        print("[angrize.py] Executing: rip: 0x%x %s" % (get_rip(state), set(self.offsets)))

    # This functions check if expr is in the from <tainted_ptr + offset>.
    # In case it is, it returns the offset found.
    def get_offset_taint(self, state, tp, expr):
        try:
            if not contains(expr, tp):
                return None
        except:
            return None

        p = self.tainted_ptrs_index(tp)
        if (p < len(self.arr) and self.arr[p]) or (p >=1 and self.arr[p-1]):
            if expr.op == '__add__' and len(expr.args) == 2:
                e = expr.args[0] if (tp == expr.args[1]).is_true() else expr.args[1]
                offset = safe_eval(state, e)
                if offset and abs(offset) < 0x5000:
                    return offset
                else:
                    return 0
            if expr.op == '__add__' and len(expr.args) == 3:
                if expr.args[2].op == 'BVV':
                    return safe_eval(state, expr.args[2])
                elif expr.args[1].op == 'BVV':
                    return safe_eval(state, expr.args[1])

        try:
            expr = state.solver.simplify(expr)
            return state.solver.eval(state.solver.simplify(expr - tp))
        except angr.errors.SimUnsatError:
            l.debug("Exception while calling the solver..")
            return None

    def get_offset(self, state, expr):
        for i, tp in enumerate(self.tainted_ptrs):
            res = self.get_offset_taint(state, tp, expr)
            if res is not None:
                return i, ctypes.c_int64(res).value

        return None, None

    def append_offset(self, offset):
        if abs(offset) >= 0x5000:
            return

        # This means: we are looking for a container_of that does not have another element after itself.
        # if (self.cof and self.disp == 0):
        #     if offset >= 0:
        #         return

        if self.align:
            offset = offset & ~0x7

        self.offsets.append(offset)

    def check_expr(self, msg, state, expr):
        i, offset = self.get_offset(state, expr)

        # If this offset depends on the last tainted pointer (our target) than we append it.
        if i is not None and i == len(self.tainted_ptrs) - 1:
            self.append_offset(offset)

        return i, offset

    def taint_register(self, state, reg, i):
        reg_name = state.arch.register_names[reg]
        if self.debug:
            print("[angrize.py] Tainting %s @ 0x%x with %s" % (reg_name,
                                                               get_rip(state),
                                                               self.tainted_ptrs[i]))
        reg_store(state, reg, self.tainted_ptrs[i])

    def inspect_address_concr(self, state):
        self.check_expr("address_concr", state, state.inspect.address_concretization_expr)
        state.inspect.address_concretization_strategy = None

    def taint_register_check(self, state, reg, i, offset):
        if i is None or i >= len(self.dep):
            return False

        # print(hex(get_rip(state)), offset, abs(self.dep[i]))
        if offset == self.dep[i]:
            self.taint_register(state, reg, i+1)
            return True

        return False

    def inspect_mem_read(self, state):
        # if get_rip(state) == 0xffffffff811f7124:
        #     import IPython
        #     IPython.embed()
        self.check_expr("mem_read", state, state.inspect.mem_read_address)

    def inspect_reg_write(self, state):
        reg = state.inspect.reg_write_offset

        if not is_general_purpose(state, reg):
            return

        # lea rax, [rbx+10]
        # mov rax, rdi
        i, offset = self.check_expr("reg_write", state, state.inspect.reg_write_expr)

        if i or offset:
            self.taint_register_check(state, reg, i, offset)
            return

        # mov rax, [rbx+10] (in this case reg_write_expr is the content of the memory)
        last_action = get_last_action(state, "mem", "read")

        if last_action:
            i, offset = self.check_expr("reg_write", state, last_action.addr)
            self.taint_register_check(state, reg, i, offset)


    def handle_exit(self, state):
        if state.inspect.exit_jumpkind == 'Ijk_NoDecode':
            l.warning("[angrize.py] NoDecode @ 0x%x" % get_rip(state))
            return

        if state.inspect.exit_jumpkind != 'Ijk_Call':
            return

        #XXX: limit the number of registers we check based on the
        #     called function prototype
        for r in [state.regs.rdi, state.regs.rsi, state.regs.rdx,
                  state.regs.rcx, state.regs.r8, state.regs.r9]:
            self.check_expr("call", state, r)

        # If this is a call to a function, we write a single 'ret'
        # instruction to the exit_target location. We also mark it as
        # 'noskip' so the exploration technique never deadens the
        # state containing the return. This avoids to run into any
        # stack alignment problems.
        state.mem[state.inspect.exit_target].uint8_t = 0xc3
        state.globals["noskip"] = True

        # These are non callee-saved registers, so we can just uninitialize them..
        # XXX: it does not hold true for calls to static functions.
        # An example is:
        # [param] struct resource->end kernel/resource.c:813:__insert_resource
        # where r9 is used after the call to __request_resource..
        # for r in ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]:
        #     bvs = state.solver.BVS("uninitialized", 64, uninitialized=True)
        #     reg_store(state, state.arch.registers[r][0], bvs)

class AngrizeGlobal(Angrize):

    def explore_global(self, global_va, global_size):
        self.global_va = global_va
        self.global_size = global_size

        self.register_bp('mem_write', angr.BP_AFTER, self.check_mem_write)
        self.register_bp('reg_write', angr.BP_AFTER, self.taint_reg_write)
        self.register_bp('mem_read', angr.BP_AFTER, self.check_mem_read)

        return super().explore()

    def taint_reg_write(self, state):
        reg = state.inspect.reg_write_offset
        if not is_general_purpose(state, reg):
            return

        # mov rax, init_task
        # mov rax, init_task+0x80
        va = safe_eval(state, state.inspect.reg_write_expr)
        if self.check_inside_global(va):
            self.taint_register(state, reg, 0)
            return

        va = None
        # mov rax, [rip+0x..]
        last_action = get_last_action(state, "mem", "read")
        if not last_action:
            return

        if self.arr[0]:
            expr = last_action.addr
            if expr.op == '__add__' and len(expr.args) == 2:
                if expr.args[0].op == 'BVV':
                    va = safe_eval(state, expr.args[0])
                elif expr.args[1].op == 'BVV':
                    va = safe_eval(state, expr.args[1])

        if va is None:
            va = safe_eval(state, last_action.addr)

        if self.check_inside_global(va):
            offset = va - self.global_va
            self.taint_register_check(state, reg, 0, offset)

    def check_mem_write(self, state):
        va = safe_eval(state, state.inspect.mem_write_address)
        self.check_inside_global(va)

    def check_mem_read(self, state):
        va = safe_eval(state, state.inspect.mem_read_address)
        self.check_inside_global(va)

    def check_inside_global(self, va):
        if va is None:
            return False

        offset = va - self.global_va
        if(len(self.dep) == 0):
            self.append_offset(offset)

        return self.global_va <= va < (self.global_va + self.global_size)

class AngrizeParam(Angrize):

    def init_reg(self, reg):
        reg = self.init_state.arch.registers[reg][0]
        reg_store(self.init_state, reg, self.tainted_ptrs[0])

    def explore_param(self, param_pos):
        pos_reg = {0: 'rdi', 1: 'rsi', 2: 'rdx', 3: 'rcx', 4: 'r8', 5: 'r9'}
        assert(param_pos <= 5)
        self.init_reg(pos_reg[param_pos])
        return super().explore()


class AngrizeRetVal(Angrize):

    def explore_retval(self, vas):
        self.target_function = vas
        self.register_bp('exit', angr.BP_BEFORE, self.taint_rax)
        return super().explore()

    def taint_rax(self, state):
        target = safe_eval(state, state.inspect.exit_target)
        if (state.inspect.exit_jumpkind == 'Ijk_Call' and target in self.target_function):
            self.taint_register(state, state.arch.registers['rax'][0], 0)
