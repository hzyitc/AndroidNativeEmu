class PthreadNativeHandler:
    def __init__(self, emu, native):
        self._emu = emu

        native.register(self.pthread_create)
        native.register(self.pthread_join)

    def pthread_create(self):
        raise NotImplementedError('Symbol hook not implemented pthread_create')

    def pthread_join(self):
        raise NotImplementedError('Symbol hook not implemented pthread_join')
