import glob
import pickle
import sys
from os.path import join as joinpath
from os.path import isfile
sys.path.append("../src/")
from elftools_wrapper import ElftoolsWrapper
import logging
import gc

# tests = ["debian", "openwrt", "android", "ubuntu"]
#tests = ["rando%d" % i for i in range(10)]
tests = ["rpi"]

def patch(EW, test, offsets_patch_file):
    for line in open(offsets_patch_file):
        struct, field, offset = line.strip().split(" ")
        offset = int(offset)
        if struct != "mm_context_t":
            struct = "struct %s" % struct

        assert(struct in EW.structs)

        was = EW.structs[struct][field]
        EW.structs[struct][field] = offset
        print("Patching for %s: %s %s %d was %d" % (test, struct, field, offset, was))

def count_test(test, outdir):
    gc.disable()
    LP = pickle.load(open("%s/log_parser.pickle" % outdir, "rb"))
    EW = pickle.load(open("%s/ew.pickle" % outdir, "rb"))
    gc.enable()

    offsets_patch_file = joinpath(outdir, "../", "data", "offsets.patch")
    if isfile(offsets_patch_file):
        patch(EW, test, offsets_patch_file)

    targets = LP.volatility_targets

    models = pickle.load(open(max(glob.glob("%s/models*" % outdir)), "rb"))
    models = dict(models)

    good = bad = np = 0

    for t in targets:
        real_offset = EW.get_offset_target(t)
        rando = "rando" if LP.is_target_randomized(t) else ""

        if real_offset == -1:
            print("%s %s not present" % (test, t))
            np += 1

        elif t not in models:
            print("%s %s %s no model" % (test, t, rando))
            bad += 1

        elif len(models[t]) == 1 and models[t][0] == real_offset:
            print("%s %s %s good" % (test, rando, t))
            good += 1

        elif (len(models[t]) == 2 or len(models[t]) == 3) and real_offset in models[t]:
            print("%s %s %s twothree" % (test, rando, t))

        else:
            bad += 1
            print("%s %s %s bad" % (test, rando, t))

    tot = len(targets)
    print("RESULT: %s tot: %d np: %d TOT present: %d good: %d bad: %d perc: %.2f" % (test, tot, np, good+bad, good, bad, good*100/(good+bad)))
    return tot, np, good, bad

def go():
    tot = np = good = bad = 0
    for t in tests:
        a, b, c, d = count_test(t, joinpath(t, "output"))
        tot += a
        np += b
        good += c
        bad += d

    tot = tot / len(tests)
    np = np / len(tests)
    good = good / len(tests)
    bad = bad / len(tests)
    print("AVERAGE tot: %d np: %d TOT present: %d good: %d bad: %d perc: %.2f" % (tot, np, good+bad, good, bad, good*100/(good+bad)))

if __name__ == "__main__":
    log = logging.getLogger()
    fh = logging.StreamHandler(open("/tmp/count_fields_accessed", "w"))
    fh.setFormatter(logging.Formatter('%(levelname)-5s | %(name)-7s | %(message)s'))
    log.addHandler(fh)
    log.setLevel(logging.DEBUG)
    log = logging.getLogger('cfa')

    go()
