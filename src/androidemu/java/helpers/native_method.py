import inspect

from unicorn import Uc
from unicorn.arm_const import *

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.jni_const import JNI_ERR
from androidemu.java.jni_ref import jobject, jstring, jobjectArray, jbyteArray, jclass
from androidemu.native.args import native_read_args


def native_write_args(emu, *argv):
    amount = len(argv)

    if amount == 0:
        return

    if amount >= 1:
        native_write_arg_register(emu, UC_ARM_REG_R0, argv[0])

    if amount >= 2:
        native_write_arg_register(emu, UC_ARM_REG_R1, argv[1])

    if amount >= 3:
        native_write_arg_register(emu, UC_ARM_REG_R2, argv[2])

    if amount >= 4:
        native_write_arg_register(emu, UC_ARM_REG_R3, argv[3])

    if amount >= 5:
        sp_start = emu.uc.reg_read(UC_ARM_REG_SP)
        sp_current = sp_start - (4 * (amount - 4))  # Reserve space for arguments.
        sp_end = sp_current

        for arg in argv[4:]:
            emu.uc.mem_write(sp_current, native_translate_arg(emu, arg).to_bytes(4, byteorder='little'))
            sp_current = sp_current + 4

        emu.uc.reg_write(UC_ARM_REG_SP, sp_end)


def native_translate_arg(emu, val):
    if isinstance(val, int):
        return val
    elif isinstance(val, str):
        return emu.java_vm.jni_env.add_local_reference(jstring(val))
    elif isinstance(val, list):
        return emu.java_vm.jni_env.add_local_reference(jobjectArray(val))
    elif isinstance(val, bytearray):
        return emu.java_vm.jni_env.add_local_reference(jbyteArray(val))
    elif isinstance(type(val), JavaClassDef):
        # TODO: Look into this, seems wrong..
        return emu.java_vm.jni_env.add_local_reference(jobject(val))
    elif isinstance(val, JavaClassDef):
        return emu.java_vm.jni_env.add_local_reference(jclass(val))
    else:
        raise NotImplementedError("Unable to write response '%s' type '%s' to emulator." % (str(val), type(val)))


def native_write_arg_register(emu, reg, val):
    emu.uc.reg_write(reg, native_translate_arg(emu, val))


def native_method(func):
    def native_method_wrapper(*argv):
        """
        :type self
        :type emu androidemu.emulator.Emulator
        :type uc Uc
        """

        emu = argv[1] if len(argv) == 2 else argv[0]
        uc = emu.uc

        args = inspect.getfullargspec(func).args
        args_count = len(args) - (2 if 'self' in args else 1)

        if args_count < 0:
            raise RuntimeError("NativeMethod accept at least (self, uc) or (uc).")

        native_args = native_read_args(uc)[:args_count]

        if len(argv) == 1:
            result = func(uc, *native_args)
        else:
            result = func(argv[0], uc, *native_args)

        if result is not None:
            native_write_arg_register(emu, UC_ARM_REG_R0, result)
        else:
            uc.reg_write(UC_ARM_REG_R0, JNI_ERR)

    return native_method_wrapper
