import logging

from androidemu.java.java_classloader import JavaClassLoader
from androidemu.java.jni_const import *
from androidemu.java.jni_env import JNIEnv
from androidemu.java.native_helper import register_func_table

logger = logging.getLogger(__name__)


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the JNIInvokeInterface table.
class JavaVM:

    """
    :type class_loader JavaClassLoader
    """
    def __init__(self, emu, class_loader):
        (self.address_ptr, self.table) = register_func_table(emu, {
            3: self.destroy_java_vm,
            4: self.attach_current_thread,
            5: self.detach_current_thread,
            6: self.get_env,
            7: self.attach_current_thread
        })

        self.jni_env = JNIEnv(emu, class_loader)

    def destroy_java_vm(self, uc):
        raise NotImplementedError()

    def attach_current_thread(self, uc):
        raise NotImplementedError()

    def detach_current_thread(self, uc):
        # TODO: NooOO idea.
        pass

    def get_env(self, uc, java_vm, env, version):
        logger.debug("java_vm: 0x%08x" % java_vm)
        logger.debug("env: 0x%08x" % env)
        logger.debug("version: 0x%08x" % version)

        uc.mem_write(env, self.jni_env.address_ptr.to_bytes(4, byteorder='little'))

        logger.debug("JavaVM->GetENV() was called!")

        return JNI_OK

    def attach_current_thread_as_daemon(self, uc):
        raise NotImplementedError()
