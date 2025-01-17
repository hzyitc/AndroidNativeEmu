import logging

from androidemu.internal.modules import Modules
from androidemu.memory.memory_manager import MemoryManager
from androidemu.native.bridge import NativeBridge

from androidemu.native.android import AndroidNativeHandler
from androidemu.native.dynlib import DynLibNativeHandler
from androidemu.native.pthread import PthreadNativeHandler
from androidemu.native.printf import PrintfNativeHandler

logger = logging.getLogger(__name__)


class NativeHandlers:

    def __init__(self, emu, memory: MemoryManager, modules: Modules, bridge: NativeBridge):
        self._emu = emu
        self._modules = modules
        self._bridge = bridge

        self.android = AndroidNativeHandler(self._emu, self)
        self.dynlib = DynLibNativeHandler(self._emu, self, modules, memory)
        self.pthread = PthreadNativeHandler(self._emu, self)
        self.printf = PrintfNativeHandler(self._emu, self)

    def register(self, func: callable, symbol_name:str=None):
        """
        Register a native function.

        Note: 
            * only affects instance created later

        Args:
            func (:obj:`callable`): function
            symbol_name (:obj:`str`, optional): symbol name to hook. 
                if this value is None, the :attr:`func` name will be used

        Return:
            :obj:`callable`: origin :attr:`func`
        """
        if symbol_name is None:
            symbol_name = func.__name__

        self._modules.add_symbol_hook(symbol_name, self._bridge.register(func))
