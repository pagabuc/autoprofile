import sys
sys.path.append("../tool")

import logging
import os
import glob
from tester import *
from access import AccessManager
from log_parser import LogParser
from layout import LayoutManager
from elftools_wrapper import ElftoolsWrapper
from utils import *
from location import Location
import pickle
import resource
import argparse
from table import main_table
from record import RecordManager
from os.path import join as joinpath
from os.path import isfile
from os.path import abspath
from dbackend import DumpBackend
from create_profile import create_profile
import gc

# XXX: there are some chains which contains i.e, struct elf64_shdr->sh_addr. We should add this as knowledge, since their offsets are alywas constant!

log = logging.getLogger('core')
RANDOMIZE = False

def load_test_list(LP, EW, guessed_targets, filter_function, filter_target):
    print("[+] Loading tests..")
    T = Tester()

    targets = LP.get_targets()
    for i, target in enumerate(targets):

        if filter_target and target != filter_target:
            continue

        sys.stdout.write('\r Loaded %d out of %d targets' % (i, len(targets)))
        sys.stdout.flush()

        real_offset = EW.get_offset_target(target)
        log.debug("Targeting: %s real_offset: %d" % (target, real_offset))

        # if real_offset == -1:
        #     continue

        if target in guessed_targets:
            log.debug("Target: %s was guessed" % target)
            continue

        for chain, dep, disp, cof, arr in LP.AM.get_accesses(target):
            loc = chain.location
            if filter_function and loc.function != filter_function:
                continue

            F = get_function(EW, LP, loc)

            if not F:
                log.debug("Cannot find %s (probably inlined)" % (loc))
                continue

            if F.name.startswith("__ia32_"):
                log.debug("skipping duplicate function %s" % (F.name))
                continue

            # If any of the depends functions of the chain were not inlined, then we skip the chain.
            if F.calls_any([EW.get_function(fd, parts_only=True) for fd in chain.depends]):
                log.debug("%s contains function which are not inlined.." % chain)
                continue

            isource = interpret_source(EW, F, chain)
            if isource is None:
                log.debug("Cannot interpret source of %s" % (chain))
                continue

            if chain.ty == "global":
                if chain.source in LP.global_arr:
                    dep = [0] + dep
                    arr = [True] + arr
                if chain.source in LP.global_ptr:
                    dep = [0] + dep

            elif chain.ptr2ptr:
                dep = [0] + dep
                arr = [False] + arr

            T.add_test(Test(target, chain, F, isource, real_offset, dep, disp, cof, arr, RANDOMIZE))

    print("")
    T.print_stats()
    return T

def print_stats(LP, EW, target_majority):
    if not debug:
        for target in LP.get_targets():
            if target not in target_majority:
                log.info("Target %s never analyzed.." % target)

    for target, major in target_majority.items():
        real_offset = EW.get_offset_target(target)
        major_str = "A" if real_offset in major else "B"
        log.debug("For target: %s major: %s %s" % (target, major_str, major))


def create_or_load_LP(datadir, outdir, functions):
    lp_file = joinpath(outdir, "log_parser.pickle")

    if isfile(lp_file):
        print("[~] Loading cached LP from %s" % (lp_file))
        return fast_pickle_load(lp_file)

    print("[+] Creating new instance of LogParser..")
    LP = LogParser(AccessManager(), RecordManager(), datadir)
    for target in get_zero_offset_targets(LP, LP.RM):
        if RANDOMIZE and LP.is_target_randomized(target):
            continue

        log.debug("[+] Deducted: %s" % target)
        LP.AM.add_knowledge(target, 0)

    for target, offset in get_all_pointers_offsets(LP, LP.RM):
        if RANDOMIZE and LP.is_target_randomized(target):
            continue

        log.debug("[+] Deducted all_pointers: %s %d" % (target, offset))
        LP.AM.add_knowledge(target, offset)

    LP.AM.finalize_stage_1(LP.not_uniq_functions, functions)
    pickle.dump(LP, open(lp_file, "wb"), protocol=pickle.HIGHEST_PROTOCOL)

    return LP

def create_or_load_EW(datadir, outdir):
    ew_file = joinpath(outdir, "ew.pickle")

    if isfile(ew_file):
        print("[~] Loading cached EW from %s" % (ew_file))
        return pickle.load(open(ew_file, 'rb'))

    if isfile(joinpath(datadir, "dump.raw")):
        EW = DumpBackend(datadir)
    else:
        EW = ElftoolsWrapper(datadir)

    del EW.dump

    pickle.dump(EW, open(ew_file, "wb"))

    return EW

def main(datadir, outdir, filter_function, filter_target, debug):

    EW = create_or_load_EW(datadir, outdir)
    functions = EW.get_functions_names()
    if "kzalloc" in functions:
        functions.remove("kzalloc")

    LP = create_or_load_LP(datadir, outdir, functions)
    LP.global_arr.add("mount_hashtable")
    LP.global_arr.add("pid_hash")
    LP.AM.finalize_stage_2()
    LP.append_new_targets()
    results = []

    guessed_targets = set()
    for target, offset in LP.AM.kb.items():
        if target in LP.get_targets():
            results.append((target, [offset]))
            guessed_targets.add(target)

    for i in range(10):
        l = logging.getLogger('core-S%d' % (i))
        LM = LayoutManager(LP.RM)

        T = load_test_list(LP, EW, guessed_targets, filter_function, filter_target)

        pickle.dump(T, open("%s/tester_step%d" % (outdir, i),"wb"))

        if len(T.tests) == 0:
            log.info("Ending the exploration, no more test loaded at step %d!!" % i)
            break

        log.info("Running step %d" % (i))
        dispy = False
        debug = False
        if filter_function != "" or filter_target != "":
            debug = True
            dispy = False

        step_results = T.run_tests(dispy=dispy, debug=debug)
        results += step_results

        pickle.dump(results, open("%s/results_step%d" % (outdir, i),"wb"))

        target_majority = get_target_majority(results)
        print_stats(LP, EW, target_majority)

        for target, major in target_majority.items():
            LM.add_target(target, list(major))

        pickle.dump(LM, open("%s/layout_manager_step%d" % (outdir, i),"wb"))

        if RANDOMIZE:
            rand = LP.randomize_layout
        else:
            rand = set()

        models = []

        for target, model in LM.layout(rand, debug=True):
            if len(model) == 2 and 0 in model:
                log.debug("Removing zero from: %s %s" % (target, model))
                model.remove(0)

            models.append((target, model))
            if EW.get_offset_target(target) in model:
                log.debug("[model] %s = %s" % (target, model))
            else:
                log.error("[model] %s = %s WRONG MODEL" % (target, model))

            if (len(model)) == 1:
                LP.AM.add_knowledge(target, model[0])

        pickle.dump(models, open("%s/models%d" % (outdir, i),"wb"))

    print("-- Creating Profile --")
    create_profile(outdir, RANDOMIZE)


def setup_logging(log_file):
    global log
    log = logging.getLogger()
    fh = logging.StreamHandler(open(log_file, "w"))
    fh.setFormatter(logging.Formatter('%(levelname)-5s | %(name)-7s | %(message)s'))
    log.addHandler(fh)
    log.setLevel(logging.DEBUG)
    log = logging.getLogger('core')

def rm_files(files):
    for f in files:
        os.remove(f)

def mkdir(d):
    if not os.path.exists(d):
        os.mkdir(d)

    rm_files(glob.glob(joinpath(d, "results_step*")))
    rm_files(glob.glob(joinpath(d, "tester_step*")))
    rm_files(glob.glob(joinpath(d, "layout_manager*")))
    rm_files(glob.glob(joinpath(d, "models*")))

def check_data_files(datadir):
    files_to_check = ["vmlinux", "pptrace.json", "plugin.json", "fields_accessed.txt", "joern.log"]
    for f in files_to_check:
        f = joinpath(datadir, f)
        if not isfile(f):
            print("Missing: %s" % (f))
            sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('testdir')
    parser.add_argument('-f', '--function', default="")
    parser.add_argument('-t', '--target', default="")
    args = parser.parse_args()

    testdir = abspath(args.testdir)
    datadir = joinpath(testdir, "data/")
    outdir = joinpath(testdir, "output/")
    check_data_files(datadir)
    mkdir(outdir)
    setup_logging(joinpath(outdir, "log"))

    debug = len(args.function + args.target) > 0

    main(datadir, outdir, args.function, args.target, debug)

    # if not debug:
    # print("-- Creating Table --")
    # main_table(args.kdir, test_dir)
