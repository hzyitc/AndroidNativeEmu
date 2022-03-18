import logging

from androidemu.hooker import Hooker
from androidemu.internal.modules import Modules
from androidemu.memory.memory_manager import MemoryManager

from androidemu.native.android import AndroidNativeHandler
from androidemu.native.dynlib import DynLibNativeHandler
from androidemu.native.pthread import PthreadNativeHandler
from androidemu.native.printf import PrintfNativeHandler

logger = logging.getLogger(__name__)


class NativeHandlers:

    def __init__(self, emu, memory: MemoryManager, modules: Modules, hooker: Hooker):
        self._emu = emu

        self.android = AndroidNativeHandler(emu, modules, hooker)
        self.dynlib = DynLibNativeHandler(emu, modules, hooker, memory)
        self.pthread = PthreadNativeHandler(emu, modules, hooker)
        self.printf = PrintfNativeHandler(emu, modules, hooker)
