
from enum import IntFlag, auto
import bisect
import copy
import logging

import logging
log = logging.getLogger('chain')

class Attr(IntFlag):
    ARR = auto()
    DOT = auto()
    COF = auto()
    REF = auto()
    VEC = auto()

    def __str__(self):
        return "".join(c.name[0] for c in Attr if self & c)

string_attrs = [("->", Attr.ARR), (".", Attr.DOT),
                ("CONTAINER_OF ", Attr.COF), ("&", Attr.REF),
                ("ARRAY ", Attr.VEC)]


class AccessChain:

    def __init__(self, location, ty, chain, source, vid, ptr2ptr, depends=[]):
        self.location = location
            
        self.ty = ty
        self.source = source
        self.chain = chain
        self.attrs = []
        self.chain_join_points = []
        self.depends_join_points = [0]

        self.vid = vid
        self.ptr2ptr = bool(ptr2ptr)
        self.depends = list(depends)
        self.fixed = False
        self.delete = False
        self.cof_id = -1
        
        if source == "get_current":
            self.ty = "global"

        if not len(chain):
            return

        for i in range(len(self.chain)):
            self.init_attrs(i)
            self.normalize_element(i)
            
        self.remove_duplicate_cof()
        
        # struct task_struct.signal|struct signal_struct->rlim|init_task
        # if ty == "global" and source != "get_current":
        #     self.attrs[0] = Attr.ARR
        #     if len(self.attrs) > 1:
        #         self.attrs[1] = 
            
        for i in range(len(self.chain)):
            struct, field = self.chain[i].split("->")
            if not len(struct) or not len(field):
                log.debug("FIX A: %s" % self)
                if i == 0:
                    self.attrs = []
                    self.chain = []
                else:
                    self.attrs = self.attrs[:i]
                    self.chain = self.chain[:i]                    
                log.debug("FIX B: %s" % self)
                break
            
    def init_attrs(self, i):
        self.attrs.append(0)
        for s, a in string_attrs:
            if s in self.chain[i]:
                self.attrs[i] |= a

    def normalize_element(self, i):
        self.chain[i] = self.chain[i].replace("CONTAINER_OF ", "")
        self.chain[i] = self.chain[i].replace("&", "")
        self.chain[i] = self.chain[i].replace("ARRAY ", "")
        self.chain[i] = self.chain[i].replace(".", "->")

    # Due to a bug in the plugin, sometimes container_of are repeated two times.
    def remove_duplicate_cof(self):
        toremove = []
        for i in range(len(self.chain) - 1):
            if self.is_container_of(i) and self.chain[i] == self.chain[i+1]:
                toremove.append(i+1)

        # if len(toremove):
        #     log.debug("DUP A %s" % self)
            
        for i in sorted(toremove, reverse=True):            
            del self.chain[i]
            del self.attrs[i]
            
        # if len(toremove):
        #     log.debug("DUP B %s" % self)

    @staticmethod
    def join(a, b, c=None, depends=None):

        new_depends = list(a.depends)
        if depends is not None:
            new_depends.append(depends)
        new_depends += list(b.depends)

        new_chain = list(a.chain) + list(b.chain)
        new_attrs = list(a.attrs) + list(b.attrs)

        if c is not None:
            new_chain += list(c.chain)
            new_attrs += list(c.attrs)

        ac = AccessChain(a.location, a.ty, new_chain, a.source, a.vid, a.ptr2ptr, new_depends)

        ac.attrs = new_attrs
        ac.chain_join_points.append(len(a.chain))
        ac.depends_join_points.append(len(new_depends))

        return ac

    def target_subchain(self, target):
        i = self.position(target)
        start, end = self.get_subchain_range(i)         
       
        cjp = bisect.bisect(self.chain_join_points, end-1)
        djp = self.depends_join_points[cjp]

        ac = copy.deepcopy(self)
        ac.chain = self.chain[ :end]
        ac.depends = self.depends[:djp]
        ac.attrs = self.attrs[:end]
        ac.chain_join_points = self.chain_join_points[:cjp]
        ac.depends_join_points = self.depends_join_points[:djp+1]

        for i in range(len(ac.chain)):
            if ac.is_container_of(i):
                break
        else:            
            ac.cof_id = -1
            
        return ac

    def __lt__(self, other):
        return ((self.location, self.ty, self.source, len(self.chain), len(self.depends)) <
                (other.location, other.ty, other.source, len(other.chain), len(other.depends)))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __len__(self):
        return len(self.chain)

    def __iter__(self):
        return iter(self.chain)

    def __hash__(self):
        return hash(str(self.location.filename) +
                    str(self.location.function) +
                    str(self.ty) +
                    str(self.source) +
                    str(self.chain) +
                    str(self.attrs) +
                    str(self.vid) +
                    str(self.depends) +
                    str(self.cof_id))

    def same_ty(self, o):
        return self.ty == o.ty

    def same_function(self, o):
        return self.location.same_function(o.location)

    def __repr__(self):
        depends = "depends: %s" % str(self.depends) if self.depends else ""

        r = "<%s %s " % (self.ty, str(self.location))
        r += "|".join(self.chain) + " | "
        r += "%s" % "-".join([str(i) for i in self.attrs]) + " | "
        r += " %s | %s>" % (self.source, depends)
        r += " ptr2ptr " if self.ptr2ptr else ""
        r += str(self.chain_join_points) if len(self.chain_join_points) else ""
        r += str(self.depends_join_points) if len(self.depends_join_points) else ""
        r += " COF_ID %d " % self.cof_id if self.cof_id >= 0 else " "
        r += " DELETE " if self.delete else " "        
        return  r

    def __getitem__(self, sliced):
        return self.chain[sliced]

    def position(self, t):
        return self.chain.index(t)

    def get_subchain_range(self, i):
        start = i
        while not self.is_arrow(start) and start > 0:
            start -= 1

        end = i + 1
        while not self.is_arrow(end) and end < len(self):
            end += 1
            
        return start, end
    
    def is_dot(self, i):
        try:
            return bool(self.attrs[i] & Attr.DOT)
        except IndexError:
            return None
        
    def is_arrow(self, i):
        try:
            return bool(self.attrs[i] & Attr.ARR)
        except IndexError:
            return None

    def is_array(self, i):
        try:
            return bool(self.attrs[i] & Attr.VEC)
        except IndexError:
            return None

    def is_ref(self, i):
        try:
            return bool(self.attrs[i] & Attr.REF)
        except IndexError:
            return None
        
    def is_container_of(self, i):
        try:
            return bool(self.attrs[i] & Attr.COF)
        except IndexError:
            return None
