from androidemu.java.helpers.native_method import native_method

class PthreadNativeHandler:
    def __init__(self, emu, modules, hooker):
        self._emu = emu

        modules.add_symbol_hook('pthread_create', hooker.write_function(self.pthread_create) + 1)
        modules.add_symbol_hook('pthread_join', hooker.write_function(self.pthread_join) + 1)

    @native_method
    def pthread_create(self):
        raise NotImplementedError('Symbol hook not implemented pthread_create')

    @native_method
    def pthread_join(self):
        raise NotImplementedError('Symbol hook not implemented pthread_join')
