import glob
import pickle
import sys
sys.path.append("../src/")
from elftools_wrapper import ElftoolsWrapper
import gc

def results(outdir):
    gc.disable()
    LP = pickle.load(open("%s/log_parser.pickle" % outdir, "rb"))
    EW = pickle.load(open("%s/ew.pickle" % outdir, "rb"))
    gc.enable()

    targets    = LP.volatility_targets
    last_model = max(glob.glob(outdir + "/models*"))
    models     = dict(pickle.load(open(last_model, "rb")))

    good = bad = np = 0

    for t in targets:
        real_offset = EW.get_offset_target(t)
        rando = "[rando]" if LP.is_target_randomized(t) else ""

        if real_offset == -1:
            print("%s not present" % (t))
            np += 1

        elif t not in models:
            print("%s %s no model" % (t, rando))
            bad += 1

        elif len(models[t]) == 1 and models[t][0] == real_offset:
            print("%s %s good" % (rando, t))
            good += 1

        elif (len(models[t]) == 2 or len(models[t]) == 3) and real_offset in models[t]:
            print("%s %s twothree" % (rando, t))

        else:
            bad += 1
            print("%s %s bad" % (rando, t))

    tot = len(targets)
    print("""[RESULT] Targets: %d Not Present: %d Present: %d Good: %d Bad: %d Perc: %.2f""" % (tot, np, good+bad,
                                                                                                good, bad,
                                                                                                good*100/(good+bad)))

if __name__ == "__main__":
    results('./output')
