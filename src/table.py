from log_parser import LogParser
from elftools_wrapper import ElftoolsWrapper
from access import AccessManager
from utils import *
import sys
import glob
import pickle
from collections import defaultdict, OrderedDict
import glob
from os.path import join as joinpath

how_many_plugins_use_cache = defaultdict(int)

def how_many_plugins_use(plugins_output, target):
    if len(how_many_plugins_use_cache) != 0:
        return how_many_plugins_use_cache[target]
    
    for log_file in glob.glob("%s/*.log" % plugins_output):
        f = open(log_file, "r")
        for l in set(f.readlines()):
            if "ACCESS: " in l:
                l = l.strip().replace("ACCESS: ", "")
                how_many_plugins_use_cache["struct " + l]+=1
        f.close()
        
    return how_many_plugins_use_cache[target]

def stats_accesses(EW, LP, accesses):
    good = ifdef = inlined = source = dep = disp = 0
    
    for chain, chain_dep, chain_disp, _, _ in accesses:
        F = get_function(EW, LP, chain.location)
        
        if LP.access_affected_ifdef(chain.location):
            ifdef+=1        
        elif not F:
            inlined+=1                
        elif interpret_source(EW, F, chain) is None:
            source+=1
        elif chain_dep is None:
            dep+=1
        elif chain_disp is None:
            disp+=1
        else:
            good+=1

    return good, ifdef, inlined, source, dep, disp

def get_model_cell(EW, target_models, target, i):
    if target not in target_models[i]:
        return "-"
    else:                
        model = target_models[i][target]
        if EW.get_offset_target(target) not in model:
            return "WRONG"
        if len(model) == 1:
            return True
        else:
            return len(model)


def is_target_randomized(LP, target):
    if LP.is_target_randomized(target):
        return r"\cmark"
    else:
        return r"\xmark"

def bf_list(l):
    res = []
    for e in l:
        if "\\" in e:
            res.append(e)
        else:
            res.append(r"\bf{%s}" % e)
            
    return res

def latex_join(l):
    return " & ".join([str(e) for e in l])

class Table():
    def __init__(self):
        self.header = []
        self.second_header = []
        self.rows = OrderedDict()
        self.steps = 0
        self.comments = []
        
    def add_header(self, h):
        self.header += h
        self.second_header = [""]*len(h)

    def add_step(self, i):
        self.header.append(r"\multicolumn{8}{|c|}{\bf{Step %i}}" % i)
        self.second_header += ["Total", "Good", "Ifdef", "Inline",
                               "Source", "Dep", "Disp", "Model"]
        self.steps += 1
        
    def add_target(self, t):
        self.rows[t] = [t]

    def add_to_target_row(self, t, row):
        self.rows[t] += row

    def __repr__(self):
        r = "%s\n%s\n" % (self.header, self.second_header)
        for row in self.rows.values():
            r+= "%s\n" % row
            
        return r

    def add_comment(self, c):
        self.comments.append(c)
        
    def write(self, test_dir, full=False):
    
        start_document = r"""\documentclass{article}
        \usepackage[paperheight=55in,paperwidth=%din,margin=1in]{geometry}
        \usepackage{makecell}
        \usepackage{pifont}
        \usepackage{xcolor}
        \definecolor{myGreen}{HTML}{006000}
        \newcommand{\cmark}{\color{myGreen}{\ding{51}}}
        \newcommand{\xmark}{\color{red}{\ding{55}}}
        \renewcommand{\arraystretch}{1.2}
        \begin{document}
        \begin{tabular}{l|cccccc|%s|}
        """ % (6+5*self.steps, "|cccccccc" * self.steps)

        tab = latex_join(bf_list(self.header)) + r"\\" + "\n"
        tab += latex_join(bf_list(self.second_header)) + r"\\" + "\hline \n"    

        # We need to rjust the rows of zero targets and targets never analized..
        max_len = max([len(x) for x in self.rows.values()])
        print(max_len)
        for target in self.rows:
            if len(self.rows[target]) != max_len:
                self.rows[target] += ["-"] * (max_len - len(self.rows[target]))

        targets = list(self.rows.keys())
        for i, target in enumerate(targets):
            # We skip targets for which we have a model
            if not full and self.rows[target][-1] == True:
                continue
            row = latex_join(self.rows[target]) + r" \\" + "\n"
            row = row.replace("False", r"\xmark")
            row = row.replace("True", r"\cmark")
            row = row.replace("_", r"\_")
            row = row.replace("->", r"$\rightarrow{}$")
            if i < len(targets) - 1 and get_struct(target) != get_struct(targets[i+1]):
                row += r"\hline" +"\n"
            tab += row

        tab += r"\end{tabular}" + "\n\n" + r"\vspace{2cm}" + "\n\n"
        
        comments = "\n\n".join(bf_list(self.comments))
        end_document = "\n\n" + r"\end{document}"

        if full:
            table_file = "%s/table_full.tex" % test_dir
        else:
            table_file = "%s/table.tex" % test_dir

        print("Saving table in: %s" % table_file)
        with open(table_file, "w") as t:
            t.write(start_document)
            t.write(tab)
            t.write(comments)
            t.write(end_document)
        
def main_table(outdir, plugins_output, RANDOMIZE):
    from core import create_or_load_LP

    LP = pickle.load(open(joinpath(outdir, "log_parser.pickle"), "rb"))
    EW = pickle.load(open(joinpath(outdir, "ew.pickle"), "rb"))
    AM = LP.AM
    RM = LP.RM
    T = Table()
    AM.finalize_stage_2()
    T.add_header(["Target", r"Offset", "Plugins", "Rand", "Const", "Zero", "All P"])
    
    targets = list(LP.get_volatility_targets())
    # We sort them for struct name and their offset inside..
    targets.sort(key=lambda x: (get_struct(x), EW.get_offset_target(x)))
    for t in targets:
        T.add_target(t)
    
    target_accesses = defaultdict(list)
    target_models = defaultdict(dict)
    steps = len(glob.glob("%s/layout_manager_step*" % outdir))

    print("Loading accessess and models from %d steps.." % steps)
    for i in range(steps):
        T.add_step(i)
        for target in targets:
            accesses = list(AM.get_accesses(target, debug=True))
            target_accesses[target].append(accesses)
                        
        LM = pickle.load(open("%s/layout_manager_step%d" % (outdir, i), "rb"))
        if RANDOMIZE:
            rand = LP.randomize_layout
        else:
            rand = set()
        
        for target, model in LM.layout(rand):            
            target_models[i][target] = model
            if (len(model)) == 1:
                AM.add_knowledge(target, model[0])

    table = []
    totals = []

    total_is_zero = 0
    total_is_all_pointers = 0
    total_models = defaultdict(int)

    all_pointers = list(dict(get_all_pointers_offsets(LP, LP.RM)).keys())
    
    print("Adding rows..")

    for target in targets:
        try:
            is_target_constant(LP, LP.RM, target)
        except:
            print("------------------ WHAT %s" % target)
            continue

        is_zero = target in get_zero_offset_targets(LP, LP.RM)
        is_all_pointer = target in all_pointers
        T.add_to_target_row(target, [EW.get_offset_target(target), how_many_plugins_use(plugins_output, target),
                                     LP.is_target_randomized(target), is_target_constant(LP, LP.RM, target),
                                     is_zero, is_all_pointer])
        if is_zero:
            total_is_zero+=1
        elif is_all_pointer:
            total_is_all_pointers+=1
        
        for i in range(steps):
            if is_zero or is_all_pointer:
                T.add_to_target_row(target, ["-"]*7 + [True])
                
            else:    
                accesses = target_accesses[target][i]
                good, ifdef, inline, source, dep, disp = stats_accesses(EW, LP, accesses)
                model_cell = get_model_cell(EW, target_models, target, i)
                T.add_to_target_row(target, [len(accesses), good, ifdef, inline, source, dep, disp, model_cell])                
                if i == steps - 1:
                    if type(model_cell) is int:
                               model_cell = "multiple"
                    total_models[model_cell] += 1

    T.add_comment("Total number of targets: %d" % len(targets))
    T.add_comment("Total number of zero offsets targets: %d" % total_is_zero)
    T.add_comment("Total number of all pointers offsets targets: %d" % total_is_all_pointers)    
    T.add_comment("Total number of correct models: %d" % total_models[True])
    T.add_comment("Total number of wrong models: %d" % total_models["WRONG"])
    T.add_comment("Total number of non uniq models: %d" % total_models["multiple"])  
    T.add_comment("Total number of targets never analized : %d" % total_models["-"])
    # statistics for comments
    T.write(outdir)
    T.write(outdir, full=True)
    
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: %s outdir plugins_output" % sys.argv[0])
        sys.exit(-1)
        
    main_table(sys.argv[1], sys.argv[2], False)
