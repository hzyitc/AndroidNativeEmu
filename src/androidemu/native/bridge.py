from unicorn import *
from unicorn.arm_const import *

from androidemu.java.helpers.native_method import native_method

class NativeBridge:
    _ITEM_SIZE = 4
    _ITEM_CONTENT = b'\x47\x00\x00\x00'

    def __init__(self, emu, base_addr, size):
        self._emu = emu
        self._base_addr = base_addr
        self._size = size

        self._callback = dict()
        self._len = 0
        self._cap = self._size // self._ITEM_SIZE

        self._emu.uc.mem_map(self._base_addr, self._size)
        self._emu.uc.hook_add(UC_HOOK_CODE, self._hook, None, self._base_addr, self._base_addr + self._size)

    def register(self, func: callable):
        """
        Register a function.

        Args:
            func (:obj:`callable`): function

        Return:
            :obj:`int`: func addr
        """
        if self._len >= self._cap:
            raise OverflowError

        index = self._len
        self._len += 1

        addr = self._base_addr + self._ITEM_SIZE * index
        self._callback[index] = native_method(func)

        self._emu.uc.mem_write(addr, self._ITEM_CONTENT)

        return addr

    def _hook(self, uc, address, size, user_data):
        offset = address - self._base_addr
        caller = uc.reg_read(UC_ARM_REG_LR)

        if offset % self._ITEM_SIZE != 0:
            raise RuntimeError("Non-aligned call at 0x%x from 0x%x" % (address, caller))

        index = offset // self._ITEM_SIZE
        if index not in self._callback:
            raise RuntimeError("Unhandled bridge call %u at 0x%x from 0x%x" % (index, address, caller))

        func = self._callback[index]
        func(self._emu)

        # return to caller
        uc.reg_write(UC_ARM_REG_PC, caller)
