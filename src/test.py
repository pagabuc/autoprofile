from utils import *
from elftools_wrapper import ElftoolsWrapper
import pickle
import sys
import gc
from layout import LayoutManager
from utils import *
import logging
gc.disable()

log = logging.getLogger()
fh = logging.StreamHandler(open("/tmp/models", "w"))
fh.setFormatter(logging.Formatter('%(levelname)-5s | %(name)-7s | %(message)s'))
log.addHandler(fh)
log.setLevel(logging.DEBUG)
log = logging.getLogger('test')

RANDOMIZE = True
outdir = sys.argv[1]

LP = pickle.load(open("%s/log_parser.pickle" % outdir, "rb"))
EW = pickle.load(open("%s/ew.pickle" % outdir, "rb"))
LM = LayoutManager(LP.RM)

i = 0
results = pickle.load(open("%s/results_step%d" % (outdir, i),"rb"))
target_majority = get_target_majority(results, n=1)

# surr = set()
# for t in LP.volatility_targets:
#     if "task_struct" in t and EW.get_offset_target(t) != -1:
#         surr.update(list(LP.get_surrounding_fields(t, n=3)))

# print(surr)

for target, major in target_majority.items():
    if "mm_struct" not in target:
        continue

    # if len(major) > 10:
    #     # print("Skipping: ", target, major)        
    #     continue
    # if (target not in LP.volatility_targets and target not in surr) or len(major) > 10:
    #     print("Skipping: ", target, major)
    #     continue
    # if EW.get_offset_target(target) >= 1000 and  EW.get_offset_target(target) <= 1600:
    # if "struct task_struct" in target:
    print(target, major)
    LM.add_target(target, list(major))

if RANDOMIZE:
    rand = LP.randomize_layout
else:
    rand = set()

# import IPython
# IPython.embed()


for target, model in LM.layout(rand, debug=True):
    if EW.get_offset_target(target) in model:
        log.debug("[model] %s = %s" % (target, model))
    else:
        log.debug("[model] %s = %s WRONG MODEL" % (target, model))
