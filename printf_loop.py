from ctypes import *
import time

msvcrt = cdll.msvcrt
counter = 0

while 1:
    msvcrt.printf("Loop iteration %d\n" % counter)
    time.sleep(1)
    counter += 1
