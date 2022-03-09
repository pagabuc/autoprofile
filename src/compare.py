import logging
l = logging.getLogger()
l.setLevel(logging.CRITICAL)
from os.path import join as joinpath
from os.path import basename as basename
from os.path import isfile
import sys
import glob
import os
from collections import Counter, defaultdict
import pickle
sys.path.append("../src/")
import gc

from elftools_wrapper import ElftoolsWrapper

VOL_BANNER="Volatility Foundation Volatility Framework 2.6.1"

GOOD = set()
BAD = set()

plugins_without_output = ["linux_malfind", "linux_check_afinfo", "linux_check_creds", "linux_check_fop", "linux_check_modules", "linux_hidden_modules", "linux_keyboard_notifiers", "linux_truecrypt_passphrase"]

def clean_output(o):
    new_output = []
    for i in list(o):
        if (i.startswith("Volatility Foundation Volatility Framework") or
            i.startswith("ACCESS: ") or
            i.startswith("WARNING : volat")):
            continue

        new_output.append(i)
    return new_output

def str_in_list(s, l):
    return any(s in e for e in l)


def get_accesses_and_output(lines):
    accesses = []
    output = []
    for line in lines:
        line = line.strip()
        if (line.startswith("WARNING :") or
            line.startswith("INFO  ") or
            line == VOL_BANNER):
            continue
        if line.startswith("ACCESS:"):
            access = line.split(": ")[1]
            accesses.append(access)
        else:
            output.append(line)

    return accesses, output

def plugin_is_unsupported(plugin, o):
    if plugin == "linux_psxview":
        return False

    return (str_in_list('SLUB is currently unsupported', o) or
            str_in_list('Traceback (most recent', o) or
            str_in_list("Invalid offset", o))

def remove_not_present_accesses(EW, accesses):
    return [t for t in accesses if EW.get_offset_target(t) != - 1]

def convert_access_in_target(LP, accesses):
    targets = []
    for access in accesses:
        for target in LP.volatility_targets:
            if target.endswith(access):
                targets.append(target)

    return targets

def get_correct_models(EW, models, accesses):
    correct_models = []
    missing = []
    for a in set(accesses):
        if a in models and len(models[a]) == 1 and models[a][0] == EW.get_offset_target(a):
            correct_models.append(a)
        else:
            missing.append(a)

    return correct_models, missing

def compare_plugins(LP, EW, p, plugin1, plugin2, models):
    o1 = open(plugin1).readlines()
    o2 = open(plugin2).readlines()

    if plugin_is_unsupported(p, o1):
        return "UNSUP", "---", "---", []

    accesses1, output1 = get_accesses_and_output(o1)
    accesses2, output2 = get_accesses_and_output(o2)

    accesses1 = set(accesses1)
    accesses2 = set(accesses2)

    # Append "struct " to those accesses which should have it.
    accesses1 = convert_access_in_target(LP, accesses1)
    accesses2 = convert_access_in_target(LP, accesses2)

    # Remove any target which is not present in the DWARF symbols
    accesses1 = remove_not_present_accesses(EW, accesses1)
    accesses2 = remove_not_present_accesses(EW, accesses2)

    model1, missing1 = get_correct_models(EW, models, accesses1)
    model2, missing2 = get_correct_models(EW, models, accesses2)

    del missing2

    good = len(model1)
    bad = len(missing1)

    if p in plugins_without_output:
        if model1 == model2 and not len(missing1):
            return "GOOD", good, bad, missing1
        else:
            return "BAD", good, bad, missing1

    if "dump_dir" in p:
        if output1 == output2 and model1 == model2 and not len(missing1):
            return "GOOD", good, bad, missing1
        else:
            return "BAD", good, bad, missing1

    if output1 == output2 and not len(missing1):
        return "GOOD",  good, bad, missing1

    if len(output1) == len(output2):
        return "CHECK",  good, bad, missing1

    return "BAD", good, bad, missing1

def compare_paper_test(test):
    gc.disable()
    LP = pickle.load(open("output/log_parser.pickle", "rb"))
    EW = pickle.load(open("output/ew.pickle", "rb"))
    gc.enable()

    targets = LP.volatility_targets

    last_model = max(glob.glob("output/models*"))
    models     = dict(pickle.load(open(last_model, "rb")))

    plugins_output = "plugins_output_%s" % test
    plugins_output_ape = "plugins_output_%s-ape" % test
    plugins_output_files = sorted(glob.glob("%s/linux_*" % plugins_output))
    plugins_output_files_ape = sorted(glob.glob("%s/linux_*" % plugins_output_ape))

    assert(len(plugins_output_files) == len(plugins_output_files_ape))

    for plugin1, plugin2 in zip(plugins_output_files, plugins_output_files_ape):
        assert(plugin1 == plugin2.replace("-ape", ""))
        p = basename(plugin1).replace(".log", "")
        outcome, good, bad, missing = compare_plugins(LP, EW, p, plugin1, plugin2, models)
        yield p, outcome, good, bad, missing

def get_symbol(outcome):
    if "GOOD" == outcome:
        return "\GOOD"
    if "BAD" in outcome:
        return "\BAD"
    if "UNSUP" in outcome:
        return "---"

    return "CHECK"

lines = defaultdict(list)
test = os.path.basename(os.getcwd())
outcomes = defaultdict(int)

for p, outcome, good, bad, missing in compare_paper_test(test):
    m = "missing: %s" % missing if len(missing)  else ""
    outcomes[outcome] += 1
    print("%30s & %s  & %s & %s %s" % (p, outcome.ljust(5), good, bad, m))
    symbol = get_symbol(outcome)
    lines[p].append("%s & %s & %s" % (symbol, good, bad))

print(outcomes)
# f = open("table2.tex", "w")
# for p in lines:
#     name = p.replace("___dump_dir_XXX", "").replace("_", "\_")
#     f.write("\\texttt{%s} & %s \\\\ \n" % (name, " & ".join(lines[p])))

# f.close()
