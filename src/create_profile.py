import pickle
from dbackend import DumpBackend
from collections import defaultdict
import glob
import sys
import re
from zipfile import ZipFile
from os.path import join as joinpath
import logging

ENUM_MODULE_STATE = ['Enumeration',
    {'choices': {0: 'MODULE_STATE_LIVE',
      1: 'MODULE_STATE_COMING',
      2: 'MODULE_STATE_GOING'},
     'target': 'int'}]

def js(struct, field):
    return "%s->%s" % (struct, field)

def ss(struct):
    return struct.replace("struct ", "")

def create_sys_map(EW):
    sys_map = ""
    for function in EW.dwarf_functions:
        for addr, _, name in EW.dwarf_functions[function]:
            sys_map+="%16x T %s\n" % (addr, name)

    return sys_map

def create_profile(outdir, RANDOMIZE):

    LP = pickle.load(open(joinpath(outdir, "log_parser.pickle"), "rb"))
    EW = pickle.load(open(joinpath(outdir, "ew.pickle"), "rb"))
    ## XXX RM also lives in LP
    LM = pickle.load(open(max(glob.glob("%s/layout_manager_step*" % outdir)), "rb"))
    exp_models = pickle.load(open(max(glob.glob("%s/models*" % outdir)), "rb"))
    exp_models = dict(exp_models)

    sys_map = create_sys_map(EW)

    RM = LM.RM

    models = defaultdict(dict)

    for target in list(LP.volatility_targets):
        if EW.get_offset_target(target) == -1:
            print("Target not present: %s" % target)
            LP.volatility_targets.remove(target)
            struct, field = target.split("->")
            models[ss(struct)] = {}

    for target, model in exp_models.items():
        if target not in LP.volatility_targets:
            continue

        struct, field = target.split("->")

        if len(model) == 1:
            models[struct][field] = model[0]
            # if EW.get_offset_target(target) != model[0]:
            #     print("Wrong offset for %s" % target)
        else:
            models[struct][field] = -1
            print("Multiple offsets for %s %s" % (target, model))

    for target in LP.volatility_targets:
        struct, field = target.split("->")
        if struct not in models or field not in models[struct]:
            print("Missing target %s" % target)
            models[struct][field] = -1

    print("-"*20)

    # Creating the vtypes for volatility
    vtypes = dict()
    for struct in models:
        vtype = {}
        for field in models[struct]:
            offset = models[struct][field]
            field_type = RM.get_field_type(js(struct, field)).strip()
            field_is_ptr = RM.is_field_pointer(js(struct, field))

            field_is_array = "[" in field_type
            field_is_ptr_of_ptr = "*" in field_type

            if field == "sk_protocol":
                vtype[field] = [offset, ['BitField', {'end_bit': 8, 'start_bit': 0}]]
            elif field == "sk_type":
                vtype[field] = [offset, ['BitField', {'end_bit': 16, 'start_bit': 0}]]

            elif field_is_array:
                try:
                    size = int(re.search("\[(\d+)\]", field_type).group(1))
                    field_type = field_type.split("[")[0].strip()
                except:
                    size = 0

                if field == "slots":
                    field_type = field_type.replace(" *", "")

                vtype[field] = [offset, ['array', size, [ss(field_type)]]]
            elif field_is_ptr_of_ptr:
                field_type = field_type.replace(" *", "")
                vtype[field] = [offset, ['pointer', ['pointer', [ss(field_type)]]]]

            elif field_is_ptr:
                vtype[field] = [offset, ['pointer', [ss(field_type)]]]
            else:
                vtype[field] = [offset, [ss(field_type)]]

        size = 10000
        if struct == "struct list_head":
            size = 16
        if struct == "struct hlist_bl_head":
            size = 8
        if struct == "struct hlist_head":
            size = 8

        vtypes[ss(struct)] = [size, vtype]

    # XXX: the following stuff should be deducted automatically..
    vtypes["atomic_t"] = [10000, {"counter": [0, ["unsigned int"]]}]
    vtypes["kuid_t"] = [10000, {"val": [0, ["unsigned int"]]}]
    vtypes["kgid_t"] = [10000, {"val": [0, ["unsigned int"]]}]

    vtypes["gate_struct64"] = [16,  {'offset_high': [8, ['unsigned int']],
                                     'offset_low': [0, ['unsigned short']],
                                     'offset_middle': [6, ['unsigned short']]}]

    print("Saving the profile in %s.." % outdir)

    with ZipFile('%s/profile.zip' % outdir, 'w') as myzip:
        myzip.writestr("vtypes.pickle", pickle.dumps(vtypes, protocol=2))
        myzip.writestr("System.map", sys_map)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s outdir" % sys.argv[0])
        sys.exit(-1)


    log = logging.getLogger()
    fh = logging.StreamHandler(open("/tmp/create_profile", "w"))
    fh.setFormatter(logging.Formatter('%(levelname)-5s | %(name)-7s | %(message)s'))
    log.addHandler(fh)
    log.setLevel(logging.DEBUG)
    log = logging.getLogger('test')

    outdir = sys.argv[1]
    create_profile(outdir, False)
