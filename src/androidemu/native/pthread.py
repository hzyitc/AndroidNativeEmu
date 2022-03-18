from androidemu.utils.autoregister import autoregister, autoregistered_do

class PthreadNativeHandler:
    def __init__(self, emu, native):
        self._emu = emu

        autoregistered_do(self, lambda func, symbol_name=None: native.register(func, symbol_name))

    @autoregister()
    def pthread_create(self):
        raise NotImplementedError('Symbol hook not implemented pthread_create')

    @autoregister()
    def pthread_join(self):
        raise NotImplementedError('Symbol hook not implemented pthread_join')
