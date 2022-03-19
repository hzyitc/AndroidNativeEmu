from typing import Dict

from androidemu.utils import memory_helpers

def register_func_table(emu, func_array: Dict[int, callable], size:int=0):
    """
    Register a array of function.

    Args
    ----
        func_array (`dict[int, callable]`): the array of functions
        size (`int`, Optional): the array size.
            if this value is 0, the max key of :attr:`func_array` will be used

    Return
    ------
        `int`: the addr of `&func_array`
        `dict[int, int]`: the addr of functions
    """
    if size == 0:
        size = int(max(func_array, key=int)) + 1

    registered = dict()
    for [ index, func ] in func_array.items():
        registered[index] = emu.bridge.register(func)

    p = emu.memory_manager.allocate(4 * (size + 1))
    table=b''
    for index in range(0, size):
        address = registered[index] if index in registered else 0
        table += int(address).to_bytes(4, byteorder='little')
    emu.uc.mem_write(p + 4, table)

    emu.uc.mem_write(p, int(p + 4).to_bytes(4, byteorder='little'))
    return p, registered
