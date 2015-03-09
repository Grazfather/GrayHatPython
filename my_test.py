import my_debugger

debugger = my_debugger.debugger()

pid = raw_input("Enter the PID of the process to attach to: ")
debugger.attach(int(pid))

printf_address = debugger.func_resolve("msvcrt.dll", "printf")
print "[*] Address of printf: 0x%08x" % printf_address

debugger.bp_set_mem(printf_address, 10)
debugger.run()
