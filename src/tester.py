import sys
import logging
import resource
import time
from angrize import AngrizeRetVal, AngrizeGlobal, AngrizeParam

l = logging.getLogger('tester')
TIMEOUT = 1200

def test_access(t):
    from angrize import AngrizeRetVal, AngrizeGlobal, AngrizeParam

    chain = t.chain
    target = t.target
    align = "flags" in target

    if t.disp:
        i = chain.chain.index(target)
        if i < len(chain) - 1:
            align |= "flags" in chain[i+1]

    if chain.ty == "retval":
        F2 = t.isource
        A = AngrizeRetVal(t.F, t.dep, t.disp, t.cof, t.arr, align)
        offsets = A.explore_retval([va for va,_ in F2.parts])

    elif chain.ty == "global":
        G = t.isource
        A = AngrizeGlobal(t.F, t.dep, t.disp, t.cof, t.arr, align)
        offsets = A.explore_global(G.va, G.size)

    elif chain.ty == "param":
        param_pos = t.isource
        A = AngrizeParam(t.F, t.dep, t.disp, t.cof, t.arr, align)
        offsets = A.explore_param(param_pos)

    # XXX
    if not t.randomize or "task_struct" in t.target:
        if 0 in offsets:
            offsets.remove(0)

    if not t.randomize and "gid" in t.target:
        if 0 in offsets:
            offsets.remove(0)
        prev = [o + 4 for o in offsets]
        offsets = sorted(set(prev + offsets))

    t.good = "GOOD" if t.real_offset in offsets else "BAD"

    t.offsets = offsets
    return t

class Tester():
    def __init__(self):
        self.tests = []
        self.container_of_tests = set()

    def add_test(self, test):
        self.tests.append(test)

    def run_tests_single_core(self):
        for t in self.tests:
            r = test_access(t)
            yield r

    def run_tests_pool(self):
        from concurrent.futures import TimeoutError
        from pebble import ProcessPool, ProcessExpired

        with ProcessPool(max_tasks=4) as pool:
            future = pool.map(test_access, self.tests, timeout=TIMEOUT)

            iterator = future.result()

            while True:
                try:
                    result = next(iterator)
                    yield result
                except StopIteration:
                    break
                except TimeoutError as error:
                    print("function took longer than %d seconds" % error.args[1])
                except ProcessExpired as error:
                    print("%s. Exit code: %d" % (error, error.exitcode))
                except Exception as error:
                    print("function raised %s" % error)
                    print(error.traceback)  # Python's traceback of remote process

        # from multiprocessing import Pool
        # with Pool(maxtasksperchild=5) as pool:
        #     for t in pool.imap_unordered(test_access, self.tests, chunksize=1):
        #         yield t

    def print_running_stats(self, good, bad, cof):
        i = good + bad + cof
        sys.stdout.write('\rDone %d/%d (%.2f) GOOD: %d BAD: %d COF: %d' % (i, len(self.tests),
                                                                           i/len(self.tests), good, bad, cof))
        sys.stdout.flush()

    def update_stats(self, t, good, bad, cof):
        if t.chain.cof_id >= 0:
            cof += 1
        elif t.good == "GOOD":
            good += 1
        else:
            bad += 1
        self.print_running_stats(good, bad, cof)
        return good, bad, cof

    def run_tests_dispy(self):
        import dispy
        dispy.MsgTimeout = 600
        cluster = dispy.JobCluster(test_access, nodes = ['A.B.C.D'],
                                   loglevel=dispy.logger.ERROR, ping_interval=20,
                                   ip_addr="X.Y.Z", secret="XXXXX", reentrant=True, pulse_interval=60)

        print("[+] Submitting dispy jobs..")
        jobs = []
        for test in self.tests:
            job = cluster.submit(test)
            jobs.append(job)
            l.debug("ID: %d %s" % (job.id, test))
            time.sleep(0.01)
        print("[+] Dispy jobs submitted")

        while len(jobs):
            for job in list(jobs):
                if job.status == dispy.DispyJob.Finished:
                    jobs.remove(job)
                    l.debug("[DISPY] RESULT JOB %s got %s" % (job.id, job.result.offsets))
                    yield job.result

                elif job.status == dispy.DispyJob.Terminated or job.status == dispy.DispyJob.Abandoned:
                    jobs.remove(job)
                    l.debug("[DISPY] TERMINATED JOB: %s from %s" % (job.id, job.exception))

                elif job.start_time is not None and time.time() - job.start_time > TIMEOUT:
                    cluster.cancel(job)
                    jobs.remove(job)
                    l.debug("[DISPY] TIMEOUT JOB: %s" % (job.id))

                elif len(jobs) < 50:
                    if job.start_time is not None:
                        remain = TIMEOUT - (int(time.time()) - int(job.start_time))
                    else:
                        remain = "NOT STARTED YET"
                    l.debug("%s %d remain: %s s" % (job.status, len(jobs), remain))

            time.sleep(1)

        cluster.close(terminate=True)

    def run_tests(self, dispy=True, debug=False):
        results = []

        if debug:
            run = self.run_tests_single_core
        elif dispy:
            run = self.run_tests_dispy
        else:
            run = self.run_tests_pool

        good = bad = cof = 0
        for t in run():
            good, bad, cof = self.update_stats(t, good, bad, cof)

            if t.chain.cof_id >= 0:
                self.container_of_tests.add(t)
                continue

            l.debug(t)
            if t.offsets != ["EXCEPTION"]:
                results.append((t.target, t.offsets))

        print("\n[+] Matching container_of...")
        for t in self.match_container_of_tests():
            l.debug(t)
            if t.offsets != ["EXCEPTION"]:
                results.append((t.target, t.offsets))

        return results


    def match_container_of_tests(self):
        cof_tests = sorted(self.container_of_tests, key=lambda x: x.chain.cof_id)
        i = 0
        matched_good = 0
        matched_bad = 0
        while i < len(cof_tests) - 1:
            t1 = cof_tests[i]
            t2 = cof_tests[i+1]
            if t1.chain.cof_id == t2.chain.cof_id:
                t1.offsets = list(set(t1.offsets + t2.offsets))
                if t1.good == "GOOD" or t2.good == "GOOD":
                    t1.good = "GOOD"
                    matched_good += 1
                    yield t1
                else:
                    matched_bad +=1
                i+=2
            else:
                # l.debug("Not matched: %s" % t1)
                i+=1

        print("GOOD match for %s container_of chains" % matched_good)
        print("BAD match for %s container_of chains" % matched_bad)

    def print_stats(self):
        if len(self.tests) == 0:
            return

        print("Loaded %s candidates to explore.." % len(self.tests))
        print("\t global: %d" % len([t for t in self.tests if t.chain.ty == "global"]))
        print("\t param: %d" % len([t for t in self.tests if t.chain.ty == "param"]))
        print("\t retval: %d" % len([t for t in self.tests if t.chain.ty == "retval"]))

        l.debug("Loaded %s candidates to explore.." % len(self.tests))
        l.debug("\t global: %d" % len([t for t in self.tests if t.chain.ty == "global"]))
        l.debug("\t param: %d" % len([t for t in self.tests if t.chain.ty == "param"]))
        l.debug("\t retval: %d" % len([t for t in self.tests if t.chain.ty == "retval"]))

class Test():

    def __init__(self, target, chain, F, isource, real_offset, dep, disp, cof, arr, randomize):
        self.target = target
        self.chain = chain
        self.F = F
        self.isource = isource
        self.real_offset = real_offset
        self.dep = dep
        self.disp = disp
        self.cof = cof
        self.arr = arr
        self.randomize = randomize
        self.offsets = []
        self.good = ""
        l.debug(self)

    def __repr__(self):
        arr = "arr: %s" % self.arr if any(self.arr) else ""

        if len(self.good):
            return "RUN: %s %s dep: %s disp: %s cof: %s %s res: %s %s" % (self.target, self.chain, self.dep,
                                                                          self.disp, self.cof, arr, self.offsets, self.good)
        else:
            return "TEST: %s %s dep: %s disp: %s cof: %s %s" % (self.target, self.chain, self.dep,
                                                             self.disp, arr, self.cof)
