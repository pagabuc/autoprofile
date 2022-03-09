import pickle
from collections import defaultdict
from utils import majority
from log_parser import LogParser
from z3 import *
import sys
import traceback

import logging
l = logging.getLogger('layout')
l.setLevel(logging.DEBUG)

### XXX Implement some form or caching..
class LayoutManager():

    def __init__(self, RM):
        self.struct_layouts = {}
        self.RM = RM

    def add_target(self, target, guess):
        struct, field = target.split("->")
        if struct not in self.struct_layouts:
            if struct in self.RM.records:
                self.struct_layouts[struct] = StructLayout(struct, self.RM)

        st = self.struct_layouts[struct]
        st.add_field(field, guess)

    def layout(self, randomize_layout, debug=True):
        if len(randomize_layout) == 0:
            print("Layout out WITHOUT randomize")
        else:
            print("Layout out WITH randomize")

        for struct, st in self.struct_layouts.items():

            randomize = struct in randomize_layout
            l.debug("[+] Laying out: %s randomized: %s" % (struct, randomize))
            try:
                for f, model in st.layout(debug=debug, randomize=randomize):
                    target = "%s->%s" % (struct, f)
                    yield target, model
            except:
                l.error("Something went wrong while laying out: %s" % struct)
                traceback.print_exc()
                continue

class StructLayout():

    def __init__(self, name, RM, depth=0):
        self.name = name
        self.RM = RM
        self.record = RM.get_record(name)
        self.record_offsets = self.record.offsets
        # self.list_head_fields = self.record.get_list_head_fields()
        self.fields_guess = dict()
        self.depth = depth

    def add_field(self, field, guess):
        if guess == []:
            return

        if field in self.record_offsets:
            # print("Adding %s->%s in %s" % (self.name, field, guess))
            self.fields_guess[field] = guess
        # else:
        #     l.error("Field is not present, check this: %s->%s!" % (self.name, field))

    def layout(self, randomize=False, debug=True):
        predicates = list()
        truths = list()
        l.debug("Modeling: %s" % self.name)

        # Here we extract the fields we are guessing, and sorting them based on their "offset"
        self.fields = sorted(self.fields_guess.keys(), key=lambda x:self.record_offsets[x])

        for i, field in enumerate(self.fields):
            guess = self.fields_guess[field]
            p = Or([Int(field) == g for g in guess])
            predicates.append((field, p))
            # solver.add(Or([var == g for g in guess]))

        for f1, f2 in zip(self.fields, self.fields[1:]):
            o1 = self.record_offsets[f1]
            o2 = self.record_offsets[f2]
            # XXX we should check what happens to unions when randomize is on..
            if o1 == o2:
                truths.append(Int(f1) == Int(f2))
            elif randomize:
                truths.append(Int(f1) != Int(f2))
            elif o1 < o2:
                truths.append(Int(f1) < Int(f2))

            if o1 == o2:
                continue

            if self.record.is_field_pointer(f1):
                if randomize:
                    for i in range(0, 8):
                        truths.append((Int(f1) + i) != Int(f2))
                else:
                    for i in range(0, 8):
                        truths.append((Int(f1) + i) < Int(f2))
                    truths.append((Int(f1) + 8) <= Int(f2))
            else:
                target = "%s->%s" % (self.name, f1)
                ptrs = self.RM.count_pointers(target)
                # print("pippo: %s %d" % (target, ptrs))
                for i in range(1, ptrs):
                    if randomize:
                        truths.append((Int(f1) + 8*i) != Int(f2))
                    else:
                        truths.append((Int(f1) + 8*i) < Int(f2))

                # The last one
                if ptrs > 0:
                    if randomize:
                        truths.append((Int(f1) + 8*ptrs) != Int(f2))
                    elif self.RM.contains_one_non_ptr_field(target):
                        truths.append((Int(f1) + 8*ptrs) < Int(f2))
                    else:
                        truths.append((Int(f1) + 8*ptrs) <= Int(f2))

        if not randomize:
            for f in self.fields:
                if self.record_offsets[f] == 0:
                    truths.append(Int(f) == 0)
                else:
                    truths.append(Int(f) > 0)

        # l.debug(truths)
        models = self.solve(truths, predicates, debug, randomize)

        fields_model = defaultdict(set)
        for model in models:
            for (f,m)  in model:
                fields_model[f].add(m)

        for f, model in fields_model.items():
            yield f, list(model)

    # https://github.com/0vercl0k/z3-playground/blob/master/z3tools.py
    def get_models(self, s, n_max = None):
        n = 0
        while s.check() == sat:
            if n_max != None and n >= n_max:
                raise TimeoutError

            m = s.model()
            yield [(f, m[Int(f)].as_long()) for f in self.fields if m[Int(f)] is not None]

            s.add(Or([sym() != m[sym] for sym in m.decls()]))
            n += 1


    def solve(self, truths, predicates, debug, randomize):
        solver = Solver()
        solver.set(unsat_core=True)
        predicates_dict = dict()

        for i, (field, p) in enumerate(predicates):
            predicates_dict['p%d'%i] = (field, p)
            solver.assert_and_track(p, 'p%d' % i)

        for t in truths:
            solver.add(t)

        models = []

        if solver.check() == sat:
            try:
                l.error("Getting models: %s" % str(solver))
                for m in self.get_models(solver, n_max=100):
                    # l.debug(m)
                    models.append(m)
            except TimeoutError:
                l.error("Model for %s timed out" % self.name)

            return models

        if hasattr(self, "depth"):
            if self.depth > 6:
                return []

        if debug:
            l.error("%s is UNSAT!!" % self.name)
            l.error(str(solver))
            l.error(solver.unsat_core())

        models = []
        # For each unsat predicate, we try to solve the model without
        # every other unsat predicate.
        unsat_core = [str(p) for p in solver.unsat_core()]
        l.error("unsat_core: %s" % unsat_core)
        for unsat_p in unsat_core:
            if len(unsat_core) > 1:
                other_unsat = [p for p in unsat_core if p != unsat_p]
                other_fields = [predicates_dict[p][0] for p in other_unsat]
            else:
                other_fields = [predicates_dict[unsat_p][0]]
            l.error("not considering: %s" % other_fields)

            l.error("recursing: %d" % self.depth)
            SL = StructLayout(self.name, self.RM, self.depth+1)

            for f, g in self.fields_guess.items():
                if f not in other_fields:
                    SL.add_field(f, g)

            model = []
            for f, m in SL.layout(randomize, debug):
                for g in m:
                    model.append((f,g))
            models.append(model)

        return models
