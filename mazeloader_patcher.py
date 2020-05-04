
import idc, idautils, idaapi

segment_name = ".text"

# Function addrs from sample e5feb48ba722996c71c55ddc8b4648cdbbc1fc382e9b0bfcae904273e10ef57d where the Control Flow Flattening was found 
# In order to limit the pattern matching into the function
init_func = 0x405DC0 
end_func  = 0x407DC9

def resolve_opaque_jnz_jz(): 

    PATTERNS = ["0F 84 ?? ?? ?? ?? 0F 85 ?? ?? ?? ??", "0F 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ??"]

    count_patched     = 0
    count_not_patched = 0

    for pattern in PATTERNS:

        ea = 0

        while ea != BADADDR:

            ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

            ''' 
            pattern: 0F 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ??
            .text:0040690E 66 21 CF            and     di, cx
            .text:00406911 0F 85 AE F4 FF FF   jnz     loc_405DC5 <- j_1_pos
            .text:00406917 0F 84 A8 F4 FF FF   jz      loc_405DC5 <- j_2_pos
            
            patched:
            .text:0040690E 66 21 CF            and     di, cx
            .text:00406911 90                  nop
            .text:00406912 90                  nop
            .text:00406913 90                  nop
            .text:00406914 90                  nop
            .text:00406915 90                  nop
            .text:00406916 90                  nop
            .text:00406917 E9 A9 F4 FF FF      jmp     loc_405DC5

            '''

            if ea_in_bounds(ea):

                # .text:00406911 0F 85 AE F4 FF FF  jnz loc_405DC5 <- j_1_pos
                #                      AE F4 FF FF                 <- j_1_value Relative offset value
                j_1_pos    = ea
                j_1_value  = Dword( j_1_pos + 0x2 )

                j_2_pos   = j_1_pos + 0x6
                j_2_value = Dword( j_2_pos + 0x2 ) 

                pos_jmp = j_1_pos + j_1_value + 0x6

                if j_1_value - j_2_value == 0x6:

                    addr_to_jmp = j_2_value + 0x1

                    # Patch the jz and jnz instructions with NOPs (12 bytes)
                    for i in range(0, 12):
                        idc.PatchByte(j_1_pos + i, 0x90)

                    # Patch with a relative jmp (size = 5) in the position of the second conditional jmp
                    idc.PatchByte (j_2_pos, 0xE9)
                    idc.PatchDword(j_2_pos + 0x1, addr_to_jmp)  

                    idc.MakeCode(ea)

                    count_patched += 1

                else:

                    count_not_patched += 1

    print "\tPatched resolve_opaque_jnz_jz: {0}".format(count_patched)
    print "\tNot Patched resolve_opaque_jnz_jz: {0}".format(count_not_patched)


def resolve_opaque_mov_push():

    PATTERNS = ["BB 00 00 00 00",
                "BB 01 00 00 00",
                "BB 02 00 00 00",
                "BB 03 00 00 00",
                "BB 04 00 00 00",
                "BB 05 00 00 00",
                "BB 06 00 00 00",
                "BB 07 00 00 00",
                "BB 08 00 00 00",
                "BB 09 00 00 00",
                "6A ?? 5B"
                    ]

    count_patched     = 0
    count_not_patched = 0

    for pattern in PATTERNS:

        ea = 0

        print pattern

        while ea != BADADDR:

            ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

            ''' pattern: BB 00 00 00 00
            .text:00406A83 BB 00 00 00 00     mov     ebx, 0
            .text:00406A88 66 01 D0           add     ax, dx
            .text:00406A8B 81 F1 B5 15 00 00  xor     ecx, 15B5h
            .text:00406A91 66 35 7A 13        xor     ax, 137Ah
            .text:00406A95 85 DB              test    ebx, ebx
            .text:00406A97 74 14              jz      short loc_406AAD

            Patched EBX > 0
            pattern: BB 09 00 00 00
            .text:00406BE3 BB 09 00 00 00     mov     ebx, 9
            .text:00406BE8 20 D1              and     cl, dl
            .text:00406BEA 66 09 D6           or      si, dx
            .text:00406BED 66 89 D6           mov     si, dx
            .text:00406BF0 85 DB              test    ebx, ebx
            .text:00406BF2 74 02              jz      short loc_406BF6

            Patched EBX == 0
            .text:00406A83 90                 nop
            .text:00406A84 90                 nop
            .text:00406A85 90                 nop
            .text:00406A86 90                 nop
            .text:00406A87 90                 nop
            .text:00406A88 90                 nop
            .text:00406A89 90                 nop
            .text:00406A8A 90                 nop
            .text:00406A8B 90                 nop
            .text:00406A8C 90                 nop
            .text:00406A8D 90                 nop
            .text:00406A8E 90                 nop
            .text:00406A8F 90                 nop
            .text:00406A90 90                 nop
            .text:00406A91 90                 nop
            .text:00406A92 90                 nop
            .text:00406A93 90                 nop
            .text:00406A94 90                 nop
            .text:00406A95 90                 nop
            .text:00406A96 90                 nop
            .text:00406A97 EB 14              jmp     short loc_406AAD

            '''

            if ea_in_bounds(ea):

                '''
                .text:00406A83 BB 00 00 00 00     mov     ebx, <0-9> <- ebx_value
                .text:00406A88 66 01 D0           add     ax, dx
                .text:00406A8B 81 F1 B5 15 00 00  xor     ecx, 15B5h
                .text:00406A91 66 35 7A 13        xor     ax, 137Ah
                .text:00406A95 85 DB              test    ebx, ebx
                .text:00406A97 74 14              jz      short loc_406AAD
                '''

                original_ea = ea

                ebx_value = Byte( ea + 1 )

                instr = idautils.DecodeInstruction(ea)

                if instr:

                    has_test = False

                    # while not jmp related instruction found
                    while ( (instr.itype <= idaapi.NN_ja) or ( instr.itype >= idaapi.NN_jmpshort) ):

                        # move to next instr
                        ea    = ea + instr.size 
                        instr = idautils.DecodeInstruction(ea)

                        # Check in order to validate that has test func and is candidate to be patched
                        if instr.itype == idaapi.NN_test:

                            has_test = True

                    # at this point "ea" variable contains the last instruction address
                    # that is the conditional jump found
                    if has_test:                
                        
                        if instr.itype == idaapi.NN_jz:

                            # ebx_value > 0 and NN_jz -> Patch with NOPs
                            if ebx_value > 0:

                                '''
                                .text:00406BE3 BB 09 00 00 00     mov     ebx, 9
                                .text:00406BE8 20 D1              and     cl, dl
                                .text:00406BEA 66 09 D6           or      si, dx
                                .text:00406BED 66 89 D6           mov     si, dx
                                .text:00406BF0 85 DB              test    ebx, ebx
                                .text:00406BF2 74 02              jz      short loc_406BF6
                                '''

                                relative_offset = ea - original_ea

                                # Patch the complete function
                                number_nops = ea - original_ea + instr.size

                                for i in range(0, number_nops):

                                    idc.PatchByte (original_ea + i, 0x90) 

                                idc.MakeCode(ea)

                            # ebx_value = 0 and NN_jz -> Patch with JMP
                            else:

                                '''
                                .text:00406A83 BB 00 00 00 00     mov     ebx, 0
                                .text:00406A88 66 01 D0           add     ax, dx
                                .text:00406A8B 81 F1 B5 15 00 00  xor     ecx, 15B5h
                                .text:00406A91 66 35 7A 13        xor     ax, 137Ah
                                .text:00406A95 85 DB              test    ebx, ebx
                                .text:00406A97 74 14              jz      short loc_406AAD
                                '''

                                # ea contains the conditional jmp address
                                relative_offset = Byte( ea + 1)

                                # NOP
                                number_nops = ea - original_ea + instr.size

                                for i in range(0, number_nops):

                                    idc.PatchByte (original_ea + i, 0x90) 

                                # Patch the conditional jmp to unconditional jmp
                                idc.PatchByte( ea , 0xEB)
                                idc.PatchByte( ea + 1, relative_offset)

                                idc.MakeCode(ea)

                            count_patched += 1

                    else:

                        count_not_patched += 1

    print "\tPatched resolve_opaque_mov_push: {0}".format(count_patched)
    print "\tNot Patched resolve_opaque_mov_push: {0}".format(count_not_patched)


def resolve_loops():

    PATTERNS = ["81 FB ?? ?? ?? ?? 75"]

    count_patched     = 0
    count_not_patched = 0

    for pattern in PATTERNS:

        ea = 0

        while ea != BADADDR:

            '''
             pattern: 81 FB ?? ?? ?? ?? 75
            .text:00406AA0 01 C7                add     edi, eax
            .text:00406AA2 66 41                inc     cx
            .text:00406AA4 43                   inc     ebx
            .text:00406AA5 81 FB A6 01 00 00    cmp     ebx, 1A6h
            .text:00406AAB 75 F3                jnz     short loc_406AA0

            patched:
            .text:00406AA0 01 C7                add     edi, eax
            .text:00406AA2 66 41                inc     cx
            .text:00406AA4 43                   inc     ebx
            .text:00406AA5 90                   nop
            .text:00406AA6 90                   nop
            .text:00406AA7 90                   nop
            .text:00406AA8 90                   nop
            .text:00406AA9 90                   nop
            .text:00406AAA 90                   nop
            .text:00406AAB 90                   nop
            .text:00406AAC 90                   nop
            '''

            ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

            if ea_in_bounds(ea):

                # Patch CMP and conditional jmp instructions in order to remove the loop
                idc.PatchByte( ea + 0, 0x90)
                idc.PatchByte( ea + 1, 0x90)
                idc.PatchByte( ea + 2, 0x90)
                idc.PatchByte( ea + 3, 0x90)
                idc.PatchByte( ea + 4, 0x90)
                idc.PatchByte( ea + 5, 0x90)
                idc.PatchByte( ea + 6, 0x90)
                idc.PatchByte( ea + 7, 0x90)

                idc.MakeCode(ea)

                count_patched += 1

    print "\tPatched resolve_loops: {0}".format(count_patched)
    print "\tNot Patched resolve_loops: {0}".format(count_not_patched)


def resolve_fs30():

    PATTERNS = ["64 ?? 30 00 00 00", "64 ?? ?? 30 00 00 00"]

    count_patched     = 0
    count_not_patched = 0

    for pattern in PATTERNS:

        ea = 0

        while ea != BADADDR:

            '''
             pattern: 64 ?? 30 00 00 00
            .text:00407644 64 A1 30 00 00 00                       mov     eax, large fs:30h
            .text:0040764A 50                                      push    eax
            .text:0040764B 80 ED AD                                sub     ch, 0ADh
            .text:0040764E B5 32                                   mov     ch, 32h
            .text:00407650 66 21 D7                                and     di, dx
            .text:00407653 5A                                      pop     edx
            .text:00407654 8A 72 02                                mov     dh, [edx+2]
            .text:00407657 84 F6                                   test    dh, dh
            .text:00407659 74 11                                   jz      short loc_40766C

             pattern: 64 ?? ?? 30 00 00 00
            .text:00406E42 64 8B 15 30 00 00 00                    mov     edx, large fs:30h
            .text:00406E49 52                                      push    edx
            .text:00406E4A 66 35 3D 1B                             xor     ax, 1B3Dh
            .text:00406E4E 20 CD                                   and     ch, cl
            .text:00406E50 28 D1                                   sub     cl, dl
            .text:00406E52 59                                      pop     ecx
            .text:00406E53 8A 51 02                                mov     dl, [ecx+2]
            .text:00406E56 84 D2                                   test    dl, dl
            .text:00406E58 74 11                                   jz      short loc_406E6B

            patched:
            .text:00406E42 64 8B 15 30 00 00 00                    mov     edx, large fs:30h
            .text:00406E49 52                                      push    edx
            .text:00406E4A 66 35 3D 1B                             xor     ax, 1B3Dh
            .text:00406E4E 20 CD                                   and     ch, cl
            .text:00406E50 28 D1                                   sub     cl, dl
            .text:00406E52 59                                      pop     ecx
            .text:00406E53 8A 51 02                                mov     dl, [ecx+2]
            .text:00406E56 84 D2                                   test    dl, dl
            .text:00406E58 EB 11                                   jmp     short loc_406E6B <-----

            '''

            ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

            if ea_in_bounds(ea):

                instr = idautils.DecodeInstruction(ea)

                if instr:

                    # while not jmp related instruction found
                    while ( (instr.itype <= idaapi.NN_ja) or ( instr.itype >= idaapi.NN_jmpshort) ):

                        # move to next instr
                        ea    = ea + instr.size 
                        instr = idautils.DecodeInstruction(ea)

                    # ea contains conditional jmp instruction
                    # Patch with relative unconditional jmp
                    idc.PatchByte(ea, 0xEB)
                    idc.MakeCode(ea)

                    count_patched += 1

                else:

                    count_not_patched += 1

    print "\tPatched resolve_fs30: {0}".format(count_patched)
    print "\tNot Patched resolve_fs30: {0}".format(count_not_patched)


def ea_in_bounds(ea):

    if segment_name == idc.SegName(ea) and ea >= init_func and ea <= end_func:

        return True

    return False


print "START SCRIPT"
print "=========================================="
print "MAZELOADER DEOBFUSCATOR"
print "=========================================="
print "TASK[0] - resolve_opaque_jnz_jz()"
resolve_opaque_jnz_jz()

print "=========================================="
print "TASK[1] - resolve_opaque_mov_push()"
resolve_opaque_mov_push()

print "=========================================="
print "TASK[2] - resolve_loops()"
resolve_loops()

print "=========================================="
print "TASK[3] - resolve_fs30()"
resolve_fs30()

print "=========================================="
print "END SCRIPT"



