import logging
import os

from androidemu.utils import memory_helpers
from androidemu.utils.autoregister import autoregister, autoregistered_do

logger = logging.getLogger(__name__)

class DynLibNativeHandler:
    def __init__(self, emu, native, modules, memory):
        self._emu = emu
        self._memory = memory
        self._modules = modules

        autoregistered_do(self, lambda func, symbol_name=None: native.register(func, symbol_name))

    @autoregister()
    def dlopen(self, uc, path):
        path = memory_helpers.read_utf8(uc, path)
        logger.debug("Called dlopen(%s)" % path)

        if path == 'libvendorconn.so':
            lib = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', 'libs', 'libvendorconn_32.so'))
            mod = self._emu.load_library(lib)

            return mod.base

        return None

    @autoregister()
    def dlclose(self, uc, handle):
        """
        The function dlclose() decrements the reference count on the dynamic library handle handle.
        If the reference count drops to zero and no other loaded libraries use symbols in it, then the dynamic library is unloaded.
        """
        logger.debug("Called dlclose(0x%x)" % handle)
        return 0

    @autoregister()
    def dladdr(self, uc, addr, info):
        logger.debug("Called dladdr(0x%x, 0x%x)" % (addr, info))

        infos = memory_helpers.read_uints(uc, info, 4)
        Dl_info = {}

        isfind = False
        for mod in self._modules.modules:
            if mod.base <= addr < mod.base + mod.size:
                dli_fname = self._memory.allocate(len(mod.filename) + 1)
                memory_helpers.write_utf8(uc, dli_fname, mod.filename + '\x00')
                memory_helpers.write_uints(uc, addr, [dli_fname, mod.base, 0, 0])
                return 1

    @autoregister()
    def dlsym(self, uc, handle, symbol):
        symbol_str = memory_helpers.read_utf8(uc, symbol)
        logger.debug("Called dlsym(0x%x, %s)" % (handle, symbol_str))

        if handle == 0xffffffff:
            sym = self._modules.find_symbol_name(symbol_str)
        else:
            module = self._modules.find_module(handle)

            if module is None:
                raise Exception('Module not found for address 0x%x' % symbol)

            sym = module.find_symbol(symbol)

        if sym is None:
            return 0

        raise NotImplementedError

    @autoregister()
    def dlerror(self):
        raise NotImplementedError('Symbol hook not implemented dlerror')
