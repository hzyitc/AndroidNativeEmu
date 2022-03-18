import logging

from androidemu.hooker import Hooker
from androidemu.internal.modules import Modules
from androidemu.java.helpers.native_method import native_method
from androidemu.memory.memory_manager import MemoryManager

from androidemu.native.android import AndroidNativeHandler
from androidemu.native.dynlib import DynLibNativeHandler
from androidemu.native.pthread import PthreadNativeHandler
from androidemu.native.printf import PrintfNativeHandler

logger = logging.getLogger(__name__)


class NativeHandlers:

    def __init__(self, emu, memory: MemoryManager, modules: Modules, hooker: Hooker):
        self._emu = emu
        self._modules = modules
        self._hooker = hooker

        self.android = AndroidNativeHandler(emu, self)
        self.dynlib = DynLibNativeHandler(emu, self, modules, memory)
        self.pthread = PthreadNativeHandler(emu, self)
        self.printf = PrintfNativeHandler(emu, self)

    def register(self, func: callable, symbol_name:str=None):
        """
        Register a native function.

        Note: 
            * only affects instance created later

        Args:
            func (:obj:`function`): function
            symbol_name (:obj:`string`, optional): symbol name to hook. 
                if this value is None, the :attr:`func` name will be used

        Return:
            :obj:`function`: origin :attr:`func`
        """
        if symbol_name is None:
            symbol_name = func.__name__

        self._modules.add_symbol_hook(symbol_name, self._hooker.write_function(native_method(func)) + 1)
