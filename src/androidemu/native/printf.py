import logging

from androidemu.utils import memory_helpers

logger = logging.getLogger(__name__)

class PrintfNativeHandler:
    def __init__(self, emu, native):
        self._emu = emu

        native.register(self.vfprintf)
        native.register(self.fprintf)

    def vfprintf(self, uc, FILE, format, va_list):
        # int vfprintf ( FILE * stream, const char * format, va_list arg );
        struct_FILE = memory_helpers.read_byte_array(uc, FILE, 18)
        c_string = memory_helpers.read_utf8(uc, format)

        args = []
        result_string = ""
        for i in range(0,len(c_string)):
            if c_string[i] == '%':
                if c_string[i+1] == "d":
                    args.append(memory_helpers.read_uints(uc,va_list,1)[0])
                elif c_string[i+1] == "c":
                    args.append(chr(memory_helpers.read_byte_array(uc,va_list,1)[0]))
                elif c_string[i+1] == "s":
                    s_addr = memory_helpers.read_ptr(uc, va_list)
                    args.append(memory_helpers.read_cString(uc, s_addr)[0])
                else:
                    result_string += c_string[i:i+2]
                    # TODO more format support
                va_list += 4
                result_string += "{0["+str(len(args)-1)+"]}"
                continue
            if i>=1:
                if c_string[i-1] == '%' or c_string[i] == '%':
                    continue
            result_string += c_string[i]

        result_string = result_string.format(args)
        logger.debug("Called vfprintf(%r)" % result_string)

    def fprintf(self):
        raise NotImplementedError('Symbol hook not implemented fprintf')
