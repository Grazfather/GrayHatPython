from idaapi import *

var_size_threshold = 16
current_address = ScreenEA()

for function in Functions(SegStart(current_address), SegEnd(current_address)):
    stack_frame = GetFrame(function)
    frame_counter = 0
    prev_count = 0

    frame_size = GetStrucSize(stack_frame)

    while frame_counter < frame_size:
        stack_var = GetMemberName(stack_frame, frame_counter)

        if stack_var != None:
            distance = frame_counter - prev_count

            if distance >= var_size_threshold:
                print "[*] Function: %s -> Stack Variable: %s (%d bytes)" % \
                    (GetFunctionName(function), prev_member, distance)

            prev_count = frame_counter
            prev_member = stack_var

            try:
                frame_counter = frame_counter + GetMemberSize(stack_frame, frame_counter)
            except:
                frame_counter += 1

        else:
            frame_counter += 1
