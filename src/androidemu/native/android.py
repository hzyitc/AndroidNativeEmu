import logging

from androidemu.native.args import native_read_args
from androidemu.utils import memory_helpers
from androidemu.utils.autoregister import autoregister, autoregistered_do

logger = logging.getLogger(__name__)

class AndroidNativeHandler:
    def __init__(self, emu, native):
        self._emu = emu

        autoregistered_do(self, lambda func, symbol_name=None: native.register(func, symbol_name))

    @autoregister("__system_property_get")
    def system_property_get(self, uc, name_ptr, buf_ptr):
        name = memory_helpers.read_utf8(uc, name_ptr)
        logger.debug("Called __system_property_get(%s, 0x%x)" % (name, buf_ptr))

        if name in self._emu.system_properties:
            memory_helpers.write_utf8(uc, buf_ptr, self._emu.system_properties[name])
        else:
            raise ValueError('%s was not found in system_properties dictionary.' % name)

        return None

    @autoregister("__android_log_print")
    def android_log_print(self, uc, log_level, log_tag_ptr, log_format_ptr):
        params_count = len(locals())
        log_tag = memory_helpers.read_utf8(uc, log_tag_ptr)
        fmt = memory_helpers.read_utf8(uc, log_format_ptr)

        args_type = []
        args_count = 0
        i = 0
        while i < len(fmt):
            if fmt[i] == '%':
                if fmt[i+1] in ['s', 'd', 'p']:
                    args_type.append(fmt[i+1])
                    args_count += 1
                    i += 1
            i += 1

        other_args = native_read_args(uc)[params_count-2:][:args_count]
        args = []
        for i in range(args_count):
            if args_type[i] == 's':
                args.append(memory_helpers.read_utf8(uc, other_args[i]))
            elif args_type[i] == 'd' or args_type[i] == 'p':
                args.append(other_args[i])

        # python not support %p format
        fmt = fmt.replace('%p', '0x%x')
        logger.debug("Called __android_log_print(%d, %s, %s)" % (log_level, log_tag, fmt % tuple(args)))

        return None
