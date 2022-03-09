from collections import defaultdict
from chain import AccessChain, Attr
from functools import partial
from utils import safe_del
import copy
import time
import logging
import sys

l = logging.getLogger('access')
l.setLevel(logging.DEBUG)
cof_id = 0

class AccessManager:

    def __init__(self):
        self.calls = defaultdict(partial(defaultdict, list)) # (filename, caller) -> [callees] -> [(position, chain)]
        self.returns = defaultdict(set) # (filename, function) -> [ret chains]
        self.chains = defaultdict(set)  # (filename, function) -> [chains]

        self.ffmap = defaultdict(set) # (function) -> filename

        self.accesses = defaultdict(list)

        self.kb = {}

    def add_access(self, chain):        
        if (chain.ty == "param" or chain.ty == "retval") and chain.is_dot(0): # stack or parameter which is not a pointer. Track rsp?
            return

        seen = set()
        for target in chain:
            if target not in self.kb and target not in seen:
                seen.add(target)                
                l.debug("[ADD] ORIG %s %s" % (target, chain))
                subchain = chain.target_subchain(target)
                l.debug("[ADD] SUBC %s %s" % (target, subchain))                
                self.accesses[target].append(subchain)

    def count_chains(self):
        return sum([len(a) for a in self.chains.values()])

    def count_accesses(self):
        return sum([len(a) for a in self.accesses.values()])

    def get_filename(self, function):
        if function not in self.ffmap:
            # print("Missing ffmap for %s" % function)
            return ""
        return list(self.ffmap[function])[0]

    def get_returns(self, function):
        filename = self.get_filename(function)
        return self.returns[filename, function]

    def get_all_chains(self, function):
        filename = self.get_filename(function)
        return self.chains[filename, function]

    def get_param_chains(self, callee, position):
        filename = self.get_filename(callee)
        for ac in list(self.chains[filename, callee]):
            if ac.ty == "param" and int(ac.source) == position:
                yield ac

    def get_retval_chains(self, filename, caller, callee):
        for ac in list(self.chains[filename, caller]):
            if ac.ty == "retval" and ac.source == callee:
                yield ac

    def clean_ffmap(self):
        for filename, caller in self.calls:
            for call_location, callee in list(self.calls[filename, caller]):
                if callee not in self.ffmap or len(self.ffmap[callee]) > 1:
                    l.debug("Cleaning from ffmap: %s" % callee)
                    safe_del(self.ffmap, callee)
                    del self.calls[filename, caller][call_location, callee]

    def clean_calls(self):
        callees = set()
        for k in self.calls:
            for call_location, callee in self.calls[k]:
                callees.add(callee)

        # print("Callers: %d Callees: %d" % (len(self.calls), len(callees)))

        for filename, caller in sorted(self.calls):
            if caller not in callees and caller not in self.functions:
                l.debug("Cleaning: %s %s" % (filename, caller))
                safe_del(self.calls, (filename, caller))
                safe_del(self.chains, (filename, caller))
                safe_del(self.returns, (filename, caller))

    def append_chain(self, filename, caller, joined, ty):
        # If an elements in depends repeats multiple times, we might be in a recursive situation.
        if len(joined.depends) != len(set(joined.depends)):
            return

        if len(joined.depends) > 8 or len(joined.chain) > 10:
            return

        if joined not in self.chains[filename, caller]:
            l.debug("[%s] %s %s" % (ty, caller, joined))
            self.chains[filename, caller].add(joined)

    def is_function_uniq(self, function):
        return function not in self.not_uniq_functions

    def join_chains(self):
        for filename, caller in self.calls:
            for call_location, callee in dict(self.calls[filename, caller]):
                # If callee is not inlined or is not unique
                if callee in self.functions or not self.is_function_uniq(callee):
                    continue
                
                callee_returns = self.get_returns(callee)
                retvals = list(self.get_retval_chains(filename, caller, callee))
                                    
                for position, arg in self.calls[filename, caller][call_location, callee]:
                    if position == -1:
                        continue
                    for param in self.get_param_chains(callee, position):
                        if param in callee_returns:
                            # [Backward + forward chains]
                            for retval in retvals:
                                joined = AccessChain.join(arg, param, retval, callee)
                                # joined = AccessChain.join(joined, ret)
                                self.append_chain(filename, caller, joined, "JOIN_BF")

                        else:
                            # [Forward chains]
                            joined = AccessChain.join(arg, param, depends=callee)
                            self.append_chain(filename, caller, joined, "JOIN_F")

                # [Backward chains]
                for ret in callee_returns:
                    if ret.ty == "param":
                        continue

                    for retval in retvals:
                        if ret.source in retval.depends:
                            continue

                        joined = AccessChain.join(ret, retval, depends=callee)
                        joined.location = call_location
                        self.append_chain(filename, caller, joined, "JOIN_B")

                        if joined.ty == "retval": #and (joined.source) not in self.calls[caller]:
                            self.calls[filename, caller][call_location, joined.source].append((-1, -1))

    def inherit_chains(self):
        for index, (filename, caller) in enumerate(self.calls):
            l.debug("Inherit from %s %d/%d" % (caller, index, len(self.calls)))
            for call_location, callee in self.calls[filename, caller]:
                if callee in self.functions or not self.is_function_uniq(callee):
                    continue

                for chain in self.get_all_chains(callee):

                    if chain.ty == "param": #and caller not in chain.depends:
                        continue

                    copied = copy.deepcopy(chain)
                    copied.location = call_location
                    copied.depends = [callee] + copied.depends
                    copied.depends_join_points = [j+1 for j in copied.depends_join_points]

                    if caller in copied.depends:
                        continue

                    self.append_chain(filename, caller, copied, "COPY")

    def finalize_stage_1(self, n, fs):
        self.not_uniq_functions = n
        self.functions = fs

        self.clean_ffmap()

        print("[+] Removing recursive calls")
        for filename, caller in self.calls:
            for call_location, callee in self.calls[filename, caller]:
                if caller == callee:
                    del self.calls[filename, caller][call_location, callee]
                    break

        print("[+] Cleaning chains")
        prev = len(self.calls) + 1
        while len(self.calls) < prev :
            prev = len(self.calls)
            self.clean_calls()

        print("[+] Joining chains..")
        prev = self.count_chains() - 1
        while prev < self.count_chains():
            prev = self.count_chains()
            self.join_chains()
            print("Number of chains: %d" % prev)

        print("[+] Inheriting chains..")
        prev = self.count_chains() - 1
        while prev < self.count_chains():
            prev = self.count_chains()
            self.inherit_chains()
            print("Number of chains: %d" % prev)

        print("[+] Removing chains of inlined functions")
        for filename, caller in list(self.chains):
            if caller not in self.functions:
                l.debug("[DEL] %s %s" % (filename, caller))
                del self.chains[filename, caller]

        print("[+] Adjusting chains with ref")
        # XX refactor with a self.list_chains() function
        for chains in self.chains.values():
            for ac in chains:
                self.adjust_chain_ref(ac)

        print("[+] Adjusting chains with cof")
        for target, chains in self.chains.items():
            for ac in list(chains):
                if ac.cof_id >= 0: # Do not duplicate already-duplicated chains.
                    continue
                duplicate = self.adjust_chain_cof(ac)
                if duplicate is not None:
                    l.debug("DUP: %s" % duplicate)
                    self.chains[target].add(duplicate)
                    
        print("[+] Adding accesses")
        for chains in self.chains.values():
            for ac in chains:
                if len(ac.chain):
                    self.add_access(ac)

        # This fixes this cases: ktime_get_boot_fast_ns struct ANON_tk_core->timekeeper|struct timekeeper->offs_boot | DR-A
        for accesses in self.accesses.values():        
            for ac in accesses:                    
                if len(ac.attrs) == 2 and ac.is_dot(0) and ac.is_ref(0) and ac.is_arrow(1):
                    ac.attrs[0] = Attr.ARR
                    ac.attrs[1] = Attr.DOT        
                    
        print("[+] Sorting accesses")
        self.sort_accesses()
        
        print("[+] Deleting unnecessary chains")
        self.delete_unnecessary_chains()              
        
    def finalize_stage_2(self):
        self.dump_chains()

    def adjust_chain_ref(self, chain):
        refs = [i for i in range(len(chain)) if chain.is_ref(i)]
                    
        for r in refs:
            if r < len(chain) - 1 and chain.is_arrow(r):
                chain.attrs[r+1] = Attr.DOT 

    def get_cof_id(self):
        global cof_id
        cof_id += 1
        return cof_id
    
    def adjust_chain_cof(self, chain):
        cofs = [i for i in range(len(chain)) if chain.is_container_of(i)]
        
        for c in cofs:
            if c < len(chain) - 1 and chain.is_arrow(c):
                duplicate = copy.deepcopy(chain)
                duplicate.attrs[c+1] = Attr.DOT
                duplicate.cof_id = chain.cof_id = self.get_cof_id()
                return duplicate
            
    def can_remove_chain(self, target, accesses, i, j):
        c1 = accesses[i]
        c2 = accesses[j]
            
        if c1.cof_id == c2.cof_id and c1.cof_id >= 0:
            return -1
        
        i1 = c1.position(target)
        i2 = c2.position(target)
        
        if i1 != i2:
            return -1
            
        d1 = set(c1.depends)
        d2 = set(c2.depends)
        intersection = d1.intersection(d2)
        
        if c1.is_ref(i1):
            # No functions are involved then we delete the first chain            
            if len(d1) == len(d2) == 0:
                return i

            # If all the functions of d2 where inlined, than we delete the first chain
            if all(f not in self.functions for f in d2):                
                return i
            # There is at least one function that was not inlined, so we keep the first chain
            else:
                return j

        if c1.ty == "retval" and c1.source not in self.functions:
            return i
            
        if len(intersection) or (len(d1) == 0 and len(d2) == 0):
            if (intersection == d1 or intersection == d2):
               return j
           
        return -1

    # For each target, it returns a list of chains of the same type belonging to the same function
    def group_accesses_function(self):
        for target, accesses in self.accesses.items():
            start = 0
            for i in range(1, len(accesses)):
                c1 = accesses[start]
                c2 = accesses[i]
                if c1.same_function(c2) and c1.same_ty(c2):
                    continue
                yield target, accesses[start:i]
                start = i

            yield target, accesses[start:i]

    def delete_unnecessary_chains(self):
        for target, accesses in self.group_accesses_function():
            for i in range(len(accesses)):
                for j in range(i+1, len(accesses)):
                    if accesses[i].delete or accesses[j].delete:
                        continue

                    l.debug("Checking %s %d %d len: %d" % (target, i, j, len(accesses)))                        
                    idx = self.can_remove_chain(target, accesses, i, j)
                    if idx >= 0:
                        accesses[idx].delete = True
                    if idx == i:
                        break
                    
            # Here we gather all those cof_id related to a chain that will be deleted
            delete_cof_ids = [c.cof_id for c in accesses if c.delete and c.cof_id >= 0]
            for c in accesses:
                if c.cof_id in delete_cof_ids:
                    c.delete = True

            l.debug("----- %s" % target)
            for c in accesses:
                l.debug("A %s" % c)
                
            #     l.debug("B %s" % c.target_subchain(target))

        for target in self.accesses:
            accesses = self.accesses[target]
            for i in sorted(range(len(accesses)), reverse=True):
                if accesses[i].delete:
                    del accesses[i]

    def sort_accesses(self):
        for target, chains in self.accesses.items():
            self.accesses[target] = sorted(set(chains))

    def get_accesses(self, target, debug=False):
        if target in self.kb:
            l.debug("we already know this target: %s" % target)
            return
            
        accesses = self.accesses[target]
        for i in sorted(range(len(accesses)), reverse=True):
            chain = accesses[i]
            idx = chain.position(target)                
            dep = self.get_dep(chain, target) 
            disp = self.get_disp(chain, target)           
            cof = chain.is_container_of(idx) or chain.is_container_of(idx-1)
            arr = [chain.is_array(i) for i in range(len(chain))]
            
            if dep is None:
                l.debug("%s %s has missing dependency.." % (target, chain))
            elif disp is None:
                l.debug("%s %s has missing displacement.." % (target, chain))

            if debug:
                yield chain, dep, disp, cof, arr
                if dep is not None and disp is not None:
                    del accesses[i]
                continue
                
            if dep is not None and disp is not None:
                del accesses[i]
                yield chain, dep, disp, cof, arr

        # for chain in list(self.accesses[target]):
        #     p = chain.position(target)
        
        #     dep = self.get_dep(chain, p)
        #     disp = self.get_disp(chain, p)
        #     cof = chain.is_container_of(p)
        #     arr = chain.is_arr_list


        #     if dep is not None and disp is not None:
        #         self.accesses[target].remove(chain)
        #         yield chain, dep, disp, cof, arr


    def add_knowledge(self, target, offset):
        self.kb[target] = int(offset)

    def dump_chains(self):
        for target in self.accesses:
            for chain in self.accesses[target]:
                l.debug("[CHAINS] %s FROM %s" % (target, chain))

    def sum_kb(self, targets):
        return sum(self.kb[t] for t in targets)

    # Calculate the displacement for a target (at position p) in a
    # chain. The displacement is the offset of our target in case of
    # nested structures.

    # The idea is that we need to sum all the components forming the
    # subchain where our target is located. If our target is the first
    # element of a subchain, then we take all the dots after (if any).
    # If our target is a dot, then we take all the offset starting
    # from the first arrow before us, and also all the dots after us.
    
    def get_disp(self, chain, target):        
        i = chain.position(target)
        start, end = chain.get_subchain_range(i)
        subchain = chain[start: end]
        subchain.remove(target)
        try:
            return self.sum_kb(subchain)
        except KeyError:
            return None

    # XXX adding the concept of subchain to AccessChain, would simplify the two following methods..

    # Calculate the dependecy for a target (at position p) in a
    # chain.  The dependecy is the chain of offsets we need to follow
    # before getting to our target (or to the "parent" of our target
    # in case of nested structures).

    # The idea is that we split the chain at every arrow to create subchains.
    # In case we know the offset of all these subchains we return them.
    # NOTE: If a subchain is not formed by only an arrow, then we need
    # to sum all its elements.
        
    def get_dep(self, chain, target):
        i = chain.position(target)
        start, end = chain.get_subchain_range(i)
        previous_subchains = set()
        for t in chain[:start]:
            s, e = chain.get_subchain_range(chain.position(t))
            previous_subchains.add((s, tuple(chain[s:e])))

        dep = []
        for start, sc in sorted(list(previous_subchains)):
            try:
                dep.append(self.sum_kb(sc))
            except KeyError:
                return None
            
        return dep
    
