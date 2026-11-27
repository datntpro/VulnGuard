import yaml
def f(data):
    # ruleid: yaml-unsafe-load
    yaml.load(data)
    # ruleid: yaml-unsafe-load
    yaml.load(data, Loader=yaml.Loader)
    # ruleid: yaml-unsafe-load
    yaml.load(data, Loader=yaml.UnsafeLoader)
    # ruleid: yaml-unsafe-load
    yaml.load(data, yaml.FullLoader)
    # ruleid: yaml-unsafe-load
    yaml.unsafe_load(data)
    # ok: yaml-unsafe-load
    yaml.safe_load(data)
    # ok: yaml-unsafe-load
    yaml.load(data, Loader=yaml.SafeLoader)
    # ok: yaml-unsafe-load
    yaml.load(data, Loader=yaml.CSafeLoader)
