import struct
import random
from immlib import *

class ioctl_hook(LogBpHook):
    def __init__(self):
        self.imm = Debugger()
        self.logfile = "C:\ioctl_log.txt"
        LogBpHook.__init__(self)

    def run(self, regs):
        """
        We use the following offsets from the ESP register to trap the
        arguments to DeviceIoControl
        ESP+4  -> hDevice
        ESP+8  -> IoControlCode
        ESP+C  -> InBuffer
        ESP+10 -> InBufferSize
        ESP+14 -> OutBuffer
        ESP+18 -> OutBufferSize
        ESP+1C -> pBytesReturned
        ESP+20 -> pOverlapped
        """

        in_buf = ""

        # read the IOCTL code
        ioctl_code = self.imm.readLong(regs['ESP'] + 8)

        # read out the InBufferSize
        inbuffer_size = self.imm.readLong(regs['ESP'] + 0x10)

        # now we find the buffer in memory to mutate
        inbuffer_ptr = self.imm.readLong(regs['ESP'] + 0xC)

        # grab the original buffer
        in_buffer = self.imm.readMemory(inbuffer_ptr, inbuffer_size)
        mutated_buffer = self.mutate(inbuffer_size)

        # write the mutated buffer into memory
        self.imm.writeMemory(inbuffer_ptr, mutated_buffer)

        # save the test case to file
        self.save_test_case(ioctl_code, inbuffer_size, in_buffer, mutated_buffer)

    def mutate(self, inbuffer_size):
        counter = 0
        mutated_buffer = ""

        # We are simply going to mutate the buffer with random bytes
        while counter < inbuffer_size:
            mutated_buffer += struct.pack("H", random.randint(0, 255))[0]
            counter += 1

        return mutated_buffer

    def save_test_case(self, ioctl_code, inbuffer_size, in_buffer, mutated_buffer):
        message = "*****\n"
        message += "IOCTL Code:\t0x%08x\n" % ioctl_code
        message += "Buffer Size:\t%d\n" % inbuffer_size
        message += "Original Buffer:\t%s\n" % in_buffer
        message += "Mutated Buffer:\t%s\n" % mutated_buffer.encode("HEX")
        message += "*****\n\n"

        fd = open(self.logfile, "a")
        fd.write(message)
        fd.close()

def main(args):
    imm = Debugger()

    deviceiocontrol = imm.getAddress("kernel32.DeviceIoControl")

    ioctl_hooker = ioctl_hook()
    ioctl_hooker.add("%08x" % deviceiocontrol, deviceiocontrol)

    return "[*] IOCTL Fuzzer Ready for Action!"
