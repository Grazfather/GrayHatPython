from immlib import *

def main(args):
    imm = Debugger()

    bad_char_found = False

    # First argument is the address to begin our search
    address = int(args[0], 16)

    # Shellcode to verify
    # Taken from http://shell-storm.org/shellcode/files/shellcode-811.php
    shellcode = "31c050682f2f7368682f62696e89e389c189c2b00bcd8031c040cd80"
    shellcode_length = len(shellcode)

    # Divide the length by two because we are hex encoding it
    # so every byte takes two characters
    debug_shellcode = imm.readMemory(address, int(shellcode_length/2))
    debug_shellcode = debug_shellcode.encode('hex')

    imm.log("Address: 0x%08x" % address)
    imm.log("Shellcode Length: %d" % shellcode_length)

    imm.log("Attack Shellcode: %s" % shellcode[:512])
    imm.log("In Memory Shellcode: %s" % debug_shellcode[:512])

    # Debug a byte-by-byte comparison of the two shellcode buffers
    count = 0
    while count < shellcode_length:
        if debug_shellcode[count] != shellcode[count]:
            imm.log("Bad Char Detected at offset %d" % count)
            bad_char_found = True
            break

        count += 1

    if bad_char_found:
        imm.log("[*****] ")
        imm.log("Bad character found: %s" % debug_shellcode[count])
        imm.log("Bad character original: %s" % shellcode[count])
        imm.log("[*****] ")

    return "[*] !badchar finished, check Log window."
