import pickle, _pickle
def f(data, fh):
    # ruleid: pickle-loads
    pickle.loads(data)
    # ruleid: pickle-loads
    pickle.load(fh)
    # ruleid: pickle-loads
    _pickle.loads(data)
    # ruleid: pickle-loads
    pickle.Unpickler(fh).load()
    # ok: pickle-loads
    pickle.dumps(data)
