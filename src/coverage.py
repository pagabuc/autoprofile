from . import ExplorationTechnique
import random

class Coverage(ExplorationTechnique):
    """
    Depth-first search.

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the longest one from deferred and continue.
    """

    def __init__(self, already_stash='already'):
        super(Coverage, self).__init__()
        self.already_stash = already_stash
        self.already_seen = set()
        
    def step(self, simgr, stash='active', **kwargs):
        print("[coverage] step was called with: %s actives\n" % simgr.stashes[stash])
        return simgr.step(stash=stash, **kwargs)
    
    def filter(self, simgr, state, **kwargs):
        # print("filter: %s" % hex(state.addr))
        if state.addr in self.already_seen:
            # print("state already seen, discarding it\n")
            return 'deadnead'
        else:
            # print("new state\n")
            self.already_seen.add(state.addr)
            return 'active'

    def step_state(self, simgr, state, **kwargs):
        print("[coverage] step_state: %s" % (state))
        step = simgr.step_state(state, **kwargs)
        print("[coverage] simgr.step_state returned: %s" % step)
        if None in step.keys():
            step[None] += step['unsat']
            step['unsat'] = []                
        print("[coverage] we return: %s\n" % step)        
        return step
