from pydbg import *
from pydbg.defines import *

import utils

# This is the maximujm number of instructions we will log
# after an access violation
MAX_INSTRUCTIONS = 10

# This is far from an exhaustive list; add more for bonus points
dangerous_functions = {
                        "strcpy" : "msvcrt.dll",
                        "strncpy" : "msvcrt.dll",
                        "sprintf" : "msvcrt.dll",
                        "vsprintf" : "msvcrt.dll"
                    }

dangerous_functions_resolved = {}
crash_encountered = False
instruction_count = 0

def danger_handler(dbg):
    # We want to print out the contents of the stack; that's about it
    # General there are only going to be a few parameters, so we will
    # take everything from ESP to ESP+20, which should give us enough
    # information to determine if we own any of the data
    esp_offset = 0
    print "[*] Hit %s" % dangerous_functions_resolved[dbg.context.Eip]
    print "================================================================"

    while esp_offset <= 20:
        parameter = dbg.smart_dereference(dbg.context.Esp + esp_offset)
        print "[ESP + %d] => %s" % (esp_offset, parameter)
        esp_offset += 4

    print "================================================================"

    dbg.suspend_all_threads()
    dbg.process_snapshot()
    dbg.resume_all_threads()

    return DBG_CONTINUE

def access_violation_handler(dbg):
    global crash_encountered

    # Something bad happened, which means something good happened :)
    # Let's handle the access violation and then restore the process
    # back to the last dangerous function that was called

    if dbg.dbg.u.Exception.dwFirstChance:
        return DBG_EXCEPTION_NOT_HANDLED

    crash_bin = utils.crash_bunning.crash_binning()
    crash_bin.record_crash(dbg)
    print crash_bin.crash_synopsis()

    if crash_encountered == False:
        dbg.suspend_all_threads()
        dbg.process_restore()
        crash_encountered = True

        # We flag each thread to single step
        for thread_id in dbg.enumerate_threads():
            print "[*] Setting single step for thread: 0x%08x" % thread_id
            h_thread = dbg.open_thread(thread_id)
            dbg.single_step(True, h_thread)
            dbg.close_handle(h_thread)

        # Now resume execution, whish will pass control to our
        # single step handler
        dbg.resume_all_threads()

        return DBG_CONTINUE

    else:
        dbg.terminate_process()

def single_step_handler(dbg):
    global instruction_count
    global crash_encountered

    if crash_encountered:
        if instruction_count == MAX_INSTRUCTIONS:
            dbg.single_step(False)
            return DBG_CONTINUE
        else:
            # Disassemble this instruction
            instruction = dbg.disasm(dbg.context.Eip)
            print "#%d\t0x%08x : %s" % (instruction_count,
                                        dbg.context.Eip,
                                        instruction)
            instruction_count += 1
            dbg.single_step(True)

    return DBG_CONTINUE

dbg = pydbg()

pid = int(raw_input("Enter the PID you wish to monitor: "))
dbg.attach(pid)

# Track down all of the dangerous functions and set breakpoints
for func in dangerous_functions.keys():
    func_address = dbg.func_resolve(dangerous_functions[func], func)
    print "[*] Resolved breakpoint: %s -> 0x%08x" % (func, func_address)
    dbg.bp_set(func_address, handler=danger_handler)
    dangerous_functions_resolved[func_address] = func

dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, access_violation_handler)
dbg.set_callback(EXCEPTION_SINGLE_STEP, single_step_handler)
dbg.run()

