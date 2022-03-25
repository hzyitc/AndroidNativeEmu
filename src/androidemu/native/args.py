from unicorn import Uc
from unicorn.arm_const import *

class native_read_args:

    def __init__(self, uc:Uc, end:int=None, begin:int=0):
        """
        Read native arguments

        Just use this as a function which will return :obj:`list`

        Note:
            * Pay attention at reg and stack because :method:`__getitem__` directly read reg or stack every time
            * If you want to use the value out of the current hook, please copy every items

        Args:
            uc (:obj:`unicorn.Uc`): Uc
            end (:obj:`int`, optional): the range of arguments. Defaults to None.
            begin (:obj:`int`, optional): the range of arguments. Defaults to 0.
        """
        self._uc = uc
        self._begin = begin
        self._end = end

    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.step is not None:
                raise ValueError("step should be 'None' instand of {}".format(type(key.step)))

            begin = self._begin
            if key.start is not None:
                begin += key.start

            end = self._end
            if key.stop is not None:
                end = end if end is not None else self._begin
                end += key.stop

            return native_read_args(self._uc, end, begin)
        elif isinstance(key, int):
            index = self._begin + key
            if self._end is not None and index >= self._end:
                raise OverflowError

            if index < 4:
                regs = [ UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3 ]
                return self._uc.reg_read(regs[index])
            else:
                sp = self._uc.reg_read(UC_ARM_REG_SP)
                index -= 4
                return int.from_bytes(self._uc.mem_read(sp + (4 * index), 4), byteorder='little')
        else:
            raise TypeError("key should be 'slice' or 'int' instand of {}".format(type(key)))

    def __iter__(self):
        return self[:]

    def __next__(self):
        if self._end is not None and self._begin >= self._end:
            raise StopIteration
        self._begin += 1
        return self[-1]

    def __str__(self):
        r = []
        for i, arg in enumerate(self):
            r.append("arg[%d]=%08X" % (i, arg))
        return '\n'.join(r)
