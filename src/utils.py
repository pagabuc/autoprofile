import hashlib
from collections import Counter, defaultdict
import logging
import os
import pickle
import gc

l = logging.getLogger('utils')

def fast_pickle_load(filename):
    gc.disable()
    with open(filename, 'rb') as f:
        p = pickle.load(f)
    gc.enable()
    return p

def safe_del(d, k):
    try:
        del d[k]
    except KeyError:
        pass

def get_struct(t):
    return t.split("->")[0]

def get_zero_offset_targets(LP, RM):
    for target, record, field in RM.iter_zero_records():
        if not LP.field_affected_ifdef(record, field):
            yield target


def get_all_pointers_offsets(LP, RM):
    for struct, record in RM.records.items():
        if not record.all_pointers:
            continue

        offset = 0
        for field_name, field_line in record.body:
            if LP.field_affected_ifdef(record, field_name):
                break
            yield "%s->%s" % (struct, field_name), offset
            offset+=8

def is_target_constant(LP, RM, target):
    struct, field = target.split("->")
    record = RM.records[struct]
    return not LP.field_affected_ifdef(record, field)

def get_function(EW, LP, loc):
    cu_funcs = None
    if not LP.is_function_uniq(loc.function):
        cu_funcs = [f for f in LP.get_cu_functions(loc.filename) if LP.is_function_uniq(f)]

    F = EW.get_function(loc.function, cu_funcs)

    return F

def interpret_source(EW, F, chain):
    ty = chain.ty
    source = chain.source

    if ty == "param" and 0 <= int(source) <= 5:
        return int(source)

    elif ty == "retval":
        F2 = EW.get_function(source, parts_only=True)
        if F2 and F.has_call_to(F2):
            return F2

    elif ty == "global":
        if source == "get_current":
            G = EW.get_global_var("init_task")
            ct = EW.get_global_var("current_task")
            F.transform_movgs(ct.va, G.va)

        elif source == "cpu_tlbstate":
            G = EW.get_global_var("cpu_tlbstate")
            F.transform_movgs_percpu(G.va)

        else:
            G = EW.get_global_var(source)
        if G:
            return G

# def get_test_dir(suffix):
#     # i = 0
#     # while os.path.exists("../results/%s%s_dumps" % (suffix, i)):
#     #     i += 1
#     # return "../results/%s%s_dumps" % (suffix, i)
#     return "../results/all/"

def md5_multiple_files(flist):
    md5s = "".join(md5_f(f) for f in flist)
    hash_obj = hashlib.md5(md5s.encode('utf-8'))
    return hash_obj.hexdigest()

def md5_f(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def intersect(target_offsets):
    return set.intersection(*map(set,target_offsets))

def get_most_commons(offsets):
    mc = Counter(offsets).most_common()
    if len(mc) == 0:
        return []

    best = mc[0][1]
    res = []
    for offset, counter in mc:
        if counter == best:
            res.append(offset)
    return res

def filter_list(l, filt):
    return [o for o in l if o not in filt]

def majority(target_offsets, n):
    # This implodes the list of list
    target_offsets = sum(target_offsets, [])

    major = []
    while len(major) < n:
        offsets = list(get_most_commons(target_offsets))
        if 0 in offsets:
            n += 1
        if offsets == []:
            break
        major += offsets
        target_offsets = filter_list(target_offsets, offsets)

    return major

def normfunc(function):
    if function.startswith("SYSC_"):
        return function.replace("SYSC_", "SyS_")
    return function

def get_target_majority(results, n=1):
    target_offsets = defaultdict(list)
    target_major = dict()
    for target, offsets in results:
        target_offsets[target].append(offsets)

    for target, target_offset in target_offsets.items():
        major = majority(target_offset, n)
        # l.debug("%s -> %s" % (target, major))
        target_major[target] = major

    return target_major
