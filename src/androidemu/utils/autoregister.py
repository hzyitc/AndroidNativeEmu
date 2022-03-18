def autoregister(*args, **kargs):
    def decorator(func):
        func._autoregister = [ args, kargs ]
        return func
    return decorator

def autoregistered_do(yourself, callback: callable):
    for methodname in dir(yourself.__class__):
        method = getattr(yourself, methodname)
        if hasattr(method, "_autoregister"):
            [ args, kargs ] = getattr(method, "_autoregister")
            callback(method, *args, **kargs)
