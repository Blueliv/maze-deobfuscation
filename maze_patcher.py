import struct
import idc
import idautils

# MAZE - Sample 1e3c7bce7eac2516c68e5586f1c22ba06e9e4bad649c5e8117393208f2eaa7bf

segment_name = ".text"


# IMPORTANT this function has to be the first one to be executed
def find_and_rename_memcpy_function():
    
    ea      = 0
    pattern = "57 56 8B 74 24 10 8B 4C 24 14 8B 7C 24 0C 8B C1 8B D1 03 C6 3B FE 76 08"

    memcpy_func_addr = None

    # Find memcpy func
    while ea != BADADDR:

        ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

        if ea and segment_name == idc.SegName(ea):

            memcpy_func_addr = ea
            idaapi.set_name(ea, "_memcpy_maze", idaapi.SN_FORCE)
            print "Pattern: {0}".format(pattern)
            print "\tPatched find_and_rename_memcpy_function: {0}".format(hex(memcpy_func_addr).split("L")[0])


    # Find all memcpy refs and resolve them.
    # This is possible to be resolved with xref IDA functions
    # But because the code is obfuscated, it will be done this way
    if memcpy_func_addr:

        '''

        .text:1001DEE1 0F 84 69 95 01 00  jz      sub_10037450
        .text:1001DEE7 0F 85 63 95 01 00  jnz     sub_10037450

        '''
        patterns          = [ "68 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 0F 85", "68 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 0F 84"]

        for pattern in patterns:

            count_patched     = 0
            count_not_patched = 0
            ea                = 0

            while ea != BADADDR:

                ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

                ''' Identify the ones that pushes the return
                    .text:1001E0EC 68 01 E1 01 10      push    offset byte_1001E101
                    .text:1001E0F1 0F 84 59 93 01 00   jz      _memcpy_maze
                    .text:1001E0F7 0F 85 53 93 01 00   jnz     _memcpy_maze
                '''

                # relative offset from first jz
                # push_instr_addr + push_instr_size + 2 (0F 84) 
                relative_offset_addr = ea + 5 + 2
                # push_inst_addr + push_instr_size + relative offset + jz_instr_size
                absolute_addr        = ea + 0x5 + Dword(relative_offset_addr) + 0x6 

                # If points to the memcpy func
                if absolute_addr == memcpy_func_addr:

                    # Copy instruction values before patching
                    values = GetManyBytes(ea, 5 + 6 + 6)


                    ''' Original
                    .text:10001574 50                 push    eax
                    .text:10001575 55                 push    ebp
                    .text:10001576 53                 push    ebx
                    .text:10001577 68 94 15 00 10     push    offset dword_10001594
                    .text:1000157C 0F 84 CE 5E 03 00  jz      _memcpy_maze
                    .text:10001582 0F 85 C8 5E 03 00  jnz     _memcpy_maze

                    The idea is to patch in order to create:
                    .text:10021905 52                 push    edx
                    .text:10021906 56                 push    esi
                    .text:10021907 50                 push    eax
                    .text:10021908 FF 15 50 74 03 10  call    dword ptr ds:_memcpy_maze
                    .text:1002190E 68 21 19 02 10     push    offset loc_10021921
                    .text:10021913 C3                 retn
                    .text:10021914 90                 nop
                    .text:10021915 90                 nop
                    .text:10021916 90                 nop
                    .text:10021917 90                 nop
                    .text:10021918 90                 nop
                    '''                  

                    # Patch push with the call _memcpy_maze
                    idc.PatchByte ( ea     , 0xFF)
                    idc.PatchByte ( ea +  1, 0x15)                  
                    idc.PatchDword( ea +  2, memcpy_func_addr)

                    # Below patch with the original push
                    # push    offset dword_714522A8
                    idc.PatchByte( ea + 6,  ord(values[0]) )
                    idc.PatchByte( ea + 7,  ord(values[1]) )
                    idc.PatchByte( ea + 8,  ord(values[2]) )
                    idc.PatchByte( ea + 9,  ord(values[3]) )
                    idc.PatchByte( ea + 10, ord(values[4]) )

                    # Add ret
                    idc.PatchByte( ea + 11, 0xC3) # 8 pos ret

                    # Nop left part of last instruction
                    idc.PatchByte( ea + 12, 0x90)
                    idc.PatchByte( ea + 13, 0x90)
                    idc.PatchByte( ea + 13, 0x90)
                    idc.PatchByte( ea + 14, 0x90)
                    idc.PatchByte( ea + 15, 0x90)
                    idc.PatchByte( ea + 16, 0x90)
                        
                    idc.MakeCode(ea)

                    count_patched += 1

                else:

                    count_not_patched += 1

            print "Pattern: {0}".format(pattern)      
            print "\tPatched find_and_rename_memcpy_function: {0}".format(count_patched)
            print "\tNot Patched find_and_rename_memcpy_function: {0}".format(count_not_patched)

def delete_fake_calls_before_jz_jnz():

    '''
    .text:714517B9 74 2C                         jz      short loc_714517E7
    .text:714517BB 75 0A                         jnz     short loc_714517C7
    .text:714517BD FF 15 0C 70 48 71             call    ds:LsaClose

    .text:71463763 75 5F                         jnz     short near ptr dword_714637C0+4
    .text:71463765 74 0A                         jz      short near ptr dword_71463770+1
    .text:71463767 FF 15 EC 71 48 71             call    ds:LsaConnectUntrusted

    74 ?? 75 ?? FF 15
    75 ?? 74 ?? FF 15

    '''

    patterns = [ "74 ?? 75 ?? FF 15", "75 ?? 74 ?? FF 15"]

    for pattern in patterns:

        count_patched     = 0
        count_not_patched = 0
        ea                = 0

        while ea != BADADDR:

            ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

            if ea and segment_name == idc.SegName(ea):
                               
                '''
                74 2C                         jz      short loc_714517E7
                75 0A                         jnz     short loc_714517C7
                FF 15 0C 70 48 71             call    ds:LsaClose

                Result:
                74 2C                         jz      short loc_714517E7
                75 0A                         jnz     short loc_714517C7
                90 90 90 90 90 90             nops 
                '''

                # Patch from pos, and delete fake calls
                pos = ea + 0x4

                patch_loop( pos, 6, 0x90)

                idc.MakeCode(ea)

                count_patched += 1

            else:

                count_not_patched += 1

        print "Pattern: {0}".format(pattern)
        print "\tPatched delete_fake_calls_before_jz_jnz: {0}".format(count_patched)
        print "\tNot Patched delete_fake_calls_before_jz_jnz: {0}".format(count_not_patched)


    '''

    .text:714713E4 0F 84 36 01 FE FF             jz      loc_71451520
    .text:714713EA 75 0A                         jnz     short near ptr loc_714713F5+1

    0F ?? ?? ?? ?? ?? 75 ?? FF 15
    0F ?? ?? ?? ?? ?? 74 ?? FF 15

    '''
    patterns = [ "0F ?? ?? ?? ?? ?? 75 ?? FF 15", "0F ?? ?? ?? ?? ?? 74 ?? FF 15"]

    for pattern in patterns:

        count_patched     = 0
        count_not_patched = 0
        ea                = 0

        while ea != BADADDR:

            ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

            if ea and segment_name == idc.SegName(ea):
                
                '''
                0F 84 36 01 FE FF             jz      loc_71451520
                75 0A                         jnz     short near ptr loc_714713F5+1
                FF 15 00 70 48 71             call    ds:EqualDomainSid

                Result:
                0F 84 36 01 FE FF             jz      loc_71451520
                75 0A                         jnz     short near ptr loc_714713F5+1
                90 90 90 90 90 90             nops
                '''

                # Patch from pos, and delete fake calls
                pos = ea + 0x8
                patch_loop( pos, 6, 0x90)               

                idc.MakeCode(ea)

                count_patched += 1

            else:

                count_not_patched += 1

        print "Pattern: {0}".format(pattern)
        print "\tPatched delete_fake_calls_before_jz_jnz: {0}".format(count_patched)
        print "\tNot Patched delete_fake_calls_before_jz_jnz: {0}".format(count_not_patched)


        '''
        .text:10021C11 0F 84 09 F9 FD FF       jz      loc_10001520
        .text:10021C17 0F 85 03 F9 FD FF       jnz     loc_10001520
        .text:10021C1D FF 15 00 91 03 10       call    ds:CreateFileW
        '''
        patterns = ["0F 84 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? FF 15", "0F 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? FF 15"]      

        for pattern in patterns:

            count_patched     = 0
            count_not_patched = 0
            ea                = 0

            while ea != BADADDR:

                ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

                if ea and segment_name == idc.SegName(ea):

                    '''
                    .text:10021C11 0F 84 09 F9 FD FF       jz      loc_10001520
                    .text:10021C17 0F 85 03 F9 FD FF       jnz     loc_10001520
                    .text:10021C1D FF 15 00 91 03 10       call    ds:CreateFileW

                    Result:
                    .text:10021C11 0F 84 09 F9 FD FF       jz      loc_10001520
                    .text:10021C17 0F 85 03 F9 FD FF       jnz     loc_10001520
                    .text:10021C1D 90                      nop
                    .text:10021C1E 90                      nop
                    .text:10021C1F 90                      nop
                    .text:10021C20 90                      nop
                    .text:10021C21 90                      nop
                    .text:10021C22 90                      nop
                    '''

                    # Patch from pos, and delete fake calls
                    pos = ea + 12

                    patch_loop( pos, 6, 0x90)

                    idc.MakeCode(ea)

                    count_patched += 1

                else:

                    count_not_patched += 1

            print "Pattern: {0}".format(pattern)
            print "\tPatched delete_fake_calls_before_jz_jnz: {0}".format(count_patched)
            print "\tNot Patched delete_fake_calls_before_jz_jnz: {0}".format(count_not_patched)


def obfuscated_jz_jnz():

    '''
    Resolve opaque predicates, in case that opaque predicate points to FF 25 the call will be patched:
    
    Example:

    .text:10001540 68 71 15 00 10      push    offset byte_10001571
    .text:10001545 0F 84 57 5C 03 00   jz      loc_100371A2
    .text:1000154B 0F 85 51 5C 03 00   jnz     loc_100371A2

    Pattern
    68 ?? ?? ?? ?? ??
    0F 84 ?? ?? ?? ??
    0F 85 ?? ?? ?? ??

    68 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 0F 85 ?? ?? ?? ??

    Operation -> DWORD( 9C 9F 01 00 ) - DWORD( 96 9F 01 00 ) == 6 

    That means that jumps to the same relative address

    0x19f9C - 0x19F96 = 0x6

    If that address points to FF 25 ?? ?? ?? ??

    .text:100371A2 FF 25 9C 90 03 10        jmp     ds:lstrlenA <----------
    .text:100371A8                          -----------------------------
    .text:100371A8 FF 25 A0 90 03 10        jmp     ds:GetModuleHandleA
    .text:100371AE                          -----------------------------
    .text:100371AE FF 25 A4 90 03 10        jmp     ds:LoadLibraryA
    .text:100371B4                          -----------------------------
    .text:100371B4
    .text:100371B4                          
    .text:100371B4                          
    .text:100371B4 FF 25 A8 90 03 10        jmp     ds:GetLastError
    .text:100371BA                          -----------------------------
    .text:100371BA FF 25 AC 90 03 10        jmp     ds:lstrcpyA

    Patch with CALL PUSH RET formula

    .text:10001540 90                       nop    ; Return addr - 0x10001571
    .text:10001541 90                       nop
    .text:10001542 90                       nop
    .text:10001543 90                       nop
    .text:10001544 90                       nop
    .text:10001545 FF 15 9C 90 03 10        call    ds:lstrlenA
    .text:1000154B 68 71 15 00 10           push    10001571h
    .text:10001550 C3                       retn

    '''

    count_patched     = 0
    count_not_patched = 0
    ea                = 0

    while ea != BADADDR:

        ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, "68 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 0F 85 ?? ?? ?? ??")

        if ea and segment_name == idc.SegName(ea):

            idc.MakeComm(ea, "Return addr - {0}".format( hex(Dword(ea + 0x1)).split("L")[0]))

            
            jz_pos    = ea + 0x5
            jz_value  = Dword( jz_pos + 0x2 )

            jnz_pos   = jz_pos + 0x6
            jnz_value = Dword( jnz_pos + 0x2 ) 

            # Check same jmp addr
            if jz_value - jnz_value == 0x6:

                pos_jmp = jz_pos + jz_value + 0x6

                # If the jmp points to a FF 25 instruction (absolute jmp)
                if Word(pos_jmp) == 0x25FF: 

                    '''
                    .text:1000153F 55                   push    ebp
                    .text:10001540 68 71 15 00 10       push    offset byte_10001571
                    .text:10001545 0F 84 57 5C 03 00    jz      loc_100371A2
                    .text:1000154B 0F 85 51 5C 03 00    jnz     loc_100371A2
                    .text:10001551 56                   push    esi
                    '''

                    # Patch the conditional jmp, copying the absolute jmp into it
                    idc.PatchWord (jz_pos, Word(pos_jmp))
                    idc.PatchDword(jz_pos + 0x2, Dword(pos_jmp + 0x2))

                    # At this point the FF 25 instruction have been copied into the conditional jmp position
                    # Ex: FF 25 3C 70 48 71 jmp     ds:CryptGenRandom
                    # But the absolute jmp will be patched with a call FF 15

                    # FF 15 call
                    idc.PatchByte (jz_pos, 0xFF)
                    idc.PatchByte (jz_pos + 0x1, 0x15)
                    
                    # Copy the push instruction where conditonal jmp was 
                    idc.PatchWord( jnz_pos, Word(ea) )
                    idc.PatchWord( jnz_pos + 0x1, Word(ea + 0x1) )
                    idc.PatchWord( jnz_pos + 0x3, Word(ea + 0x3) )
                    idc.PatchByte( jnz_pos + 0x5, 0xC3)

                    # Nop the first 5 bytes. 
                    patch_loop(ea, 0x5, 0x90)

                    '''
                    .text:10001540 90                  nop                     ; Return addr - 0x10001571
                    .text:10001541 90                  nop
                    .text:10001542 90                  nop
                    .text:10001543 90                  nop
                    .text:10001544 90                  nop
                    .text:10001545 FF 15 9C 90 03 10   call    ds:lstrlenA
                    .text:1000154B 68 71 15 00 10      push    10001571h
                    .text:10001550 C3                  retn
                    '''

                    idc.MakeCode(ea)

                else:

                    '''
                    .text:10021C0C 68 27 1C 02 10         push    offset loc_10021C27
                    .text:10021C11 0F 84 09 F9 FD FF      jz      loc_10001520
                    .text:10021C17 0F 85 03 F9 FD FF      jnz     loc_10001520

                    .text:10021C0C 90                     nop
                    .text:10021C0D 90                     nop
                    .text:10021C0E 90                     nop
                    .text:10021C0F 90                     nop
                    .text:10021C10 90                     nop
                    .text:10021C11 90                     nop
                    .text:10021C12 90                     nop
                    .text:10021C13 90                     nop
                    .text:10021C14 90                     nop
                    .text:10021C15 90                     nop
                    .text:10021C16 90                     nop
                    .text:10021C17 E9 04 F9 FD FF         jmp     loc_10001520
                    .text:10021C1C 90                     nop   <- last byte of old jnz instr
                    '''

                    # The first 11 bytes to nop

                    for i in range(0,11):

                        idc.PatchByte (ea + i, 0x90)

                    # Add 1 to the address, because the size of the conditional jmp is 6, and the size of the unconditional jmp is 5
                    addr_to_jmp = Dword( jnz_pos + 0x2) + 0x1 

                    # Patch first jz_value with unconditional jmp
                    idc.PatchByte (jnz_pos, 0xE9)

                    # Set the relative address
                    idc.PatchDword(jnz_pos + 0x1, addr_to_jmp)

                    # Last byte of the jnz to NOP (0x90)
                    idc.PatchByte (jnz_pos + 0x5  , 0x90)

                    idc.MakeCode(ea)

                    '''
                    .text:10021C0C 90                     nop
                    .text:10021C0D 90                     nop
                    .text:10021C0E 90                     nop
                    .text:10021C0F 90                     nop
                    .text:10021C10 90                     nop
                    .text:10021C11 90                     nop
                    .text:10021C12 90                     nop
                    .text:10021C13 90                     nop
                    .text:10021C14 90                     nop
                    .text:10021C15 90                     nop
                    .text:10021C16 90                     nop
                    .text:10021C17 E9 04 F9 FD FF         jmp     loc_10001520
                    .text:10021C1C 90                     nop   <- last byte of old jnz instr
                    '''

                count_patched += 1

            else:

                count_not_patched += 1


    print "\tPatched obfuscated_jz_jnz: {0}".format(count_patched)
    print "\tNot Patched obfuscated_jz_jnz: {0}".format(count_not_patched)


def patch_jmp_eax():

    '''
    
    This type of push + jmp eax can be found in the maze code

    .text:71452297 68 A8 22 45 71 push    offset dword_714522A8
    .text:7145229C FF E0          jmp     eax

    With this patter the script is able to find this type of code:

    68 ?? ?? ?? ?? FF E0

    '''

    count_patched     = 0
    count_not_patched = 0
    ea                = 0

    while ea != BADADDR:

        ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, "68 ?? ?? ?? ?? FF E0")

        if ea and segment_name == idc.SegName(ea):

            '''
            68 A8 22 45 71 push    offset dword_714522A8
            FF E0          jmp     eax

            in some cases we found this after the jmp fake api calls
            FF 15 08 90 03 10      call    ds:LsaAddAccountRights
            '''

            # push + jmp = 7 bytes
            # call Fake api call = 6 bytes
            # Store the byte values in "values" list
            values = GetManyBytes(ea, 7 + 6)

            '''
            FF D0          call    eax
            68 A8 22 45 71 push    offset dword_714522A8
            C3             ret
            '''

            # Patch with call eax
            idc.PatchByte( ea      , 0xFF)
            idc.PatchByte( ea + 0x1, 0xD0)

            # Patch push
            idc.PatchByte( ea + 0x2, ord(values[0]) )
            idc.PatchByte( ea + 0x3, ord(values[1]) )
            idc.PatchByte( ea + 0x4, ord(values[2]) )
            idc.PatchByte( ea + 0x5, ord(values[3]) )
            idc.PatchByte( ea + 0x6, ord(values[4]) )

            # Patch ret
            idc.PatchByte( ea + 0x7, 0xC3)

            '''
            If the script found in the position 7 and 8 FF 15 that means that it has found a fake api call
            
            57                   push    edi
            A1 D4 90 03 10       mov     eax, ds:lstrcatW
            89 C6                mov     esi, eax
            68 C9 28 00 10       push    offset loc_100028C9
            FF E0                jmp     eax
            FF 15 08 90 03 10    call    ds:LsaAddAccountRights
            91                   xchg    eax, ecx
            23 00                and     eax, [eax]
            '''

            # NOP the fake call 
            if ord(values[7]) == 0xFF and ord(values[8]) == 0x15:

                for i in range(0, 5):

                    idc.PatchByte( ea + 0x8 + i, 0x90)

            idc.MakeCode(ea)
            count_patched += 1

        else:
            count_not_patched += 1

    print "\tPatched patch_jmp_eax: {0}".format(count_patched)
    print "\tNot Patched patch_jmp_eax: {0}".format(count_not_patched)


def obfuscated_jz_jnz_2():

    patterns = [ "68 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 75 ??", "68 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 74 ??" ]

    for pattern in patterns:

        ea                = 0
        count_patched     = 0
        count_not_patched = 0

        '''

        It is assumed, after analysis, that the following conditions are met.

        - The first jz  or jnz instruction is the one that contains the final address.
        - The second jz or jnz instruction contains the intermediate address,
        this intermediate address contains another conditional jmp instruction 
        that points to the same final address as the first conditional jmp instruction.    

        .text:1002AFE3 68 1D B0 02 10     push  offset loc_1002B01D
        .text:1002AFE8 0F 84 12 6E 00 00  jz    loc_10031E00        <- jmp to Final Addr
        .text:1002AFEE 75 04              jnz   short loc_1002AFF4  <- jmp to Intermediate Addr
        .text:1002AFF0 E2 1B              loop  loc_1002B00D

        .text:1002AFF2 00                 db    0
        .text:1002AFF3 00                 db    0

        .text:1002AFF4
        .text:1002AFF4                         loc_1002AFF4:
        .text:1002AFF4 0F 85 06 6E 00 00  jnz  loc_10031E00        <- jmp to Final Addr
        .text:1002AFFA 74 04              jz   short loc_1002B000  <- Junk Code
        .text:1002AFFC 13 1A              adc  ebx, [edx]

        '''

        while ea != BADADDR:

            ea = idc.FindBinary(ea, SEARCH_NEXT|SEARCH_DOWN|SEARCH_CASE, pattern)

            if ea and segment_name == idc.SegName(ea):

                # First push
                push_addr = ea

                # First conditional jmp (jz or jnz)
                first_j = ea + 0x5 

                # Second conditional jmp (jz or jnz)
                second_j = first_j + 0x6

                # pos contains the last position
                pos = 0xFFFFFFFF & first_j + Dword(first_j + 0x2) + 0x6
                
                # pos_2 contains the intermediate position before jmp to the final pos
                pos_2 = 0xFFFFFFFF & first_j + 0x6 + 0x2 + Byte(first_j + 0x6 + 0x1)
                
                # First opcode intermediate instruction
                value_pos_2 = Byte(pos_2)

                # Final address
                pos_3 = pos_2 + Dword(pos_2 + 0x2) + 0x6 

                # If the OPCODE value of the intermediate jmp instruction begins with 0x0F must be patched
                if value_pos_2 == 0xF:

                    value_pos_final = Word(pos_3)

                    # If the final address first two bytes values are FF 25 (absolute jmp) 
                    # Patch with call push ret formula
                    if value_pos_final == 0x25FF:

                        '''
                        .text:1002D25D 68 9C D2 02 10                          push    offset dword_1002D29C
                        .text:1002D262 0F 84 A6 9F 00 00                       jz      loc_1003720E  <------ jmp     ds:GetTickCount
                        .text:1002D268 75 04                                   jnz     short loc_1002D26E
                        .text:1002D26A 86 01                                   xchg    al, [ecx]
                        .text:1002D26C 00                                      db    0
                        .text:1002D26D 00                                      db    0
                        .text:1002D26E
                        .text:1002D26E                         loc_1002D26E:                          
                        .text:1002D26E 0F 85 9A 9F 00 00                       jnz     loc_1003720E   <------ jmp     ds:GetTickCount
                        .text:1002D274 74 0A                                   jz      short loc_1002D280
                        .text:1002D276 FF 15 10 92 03 10                       call    ds:EnumChildWindows


                        The first conditional jmp and the intermediate points to WinAPI function:
                        .text:1003720E FF 25 E4 90 03 10                       jmp     ds:GetTickCount

                        Patched:

                        .text:1002D25D 90                                      nop
                        .text:1002D25E 90                                      nop
                        .text:1002D25F 90                                      nop
                        .text:1002D260 90                                      nop
                        .text:1002D261 90                                      nop
                        .text:1002D262 FF 15 E4 90 03 10                       call    ds:GetTickCount
                        .text:1002D268 68 9C D2 02 10                          push    1002D29Ch
                        .text:1002D26D C3                                      retn
                        .text:1002D26E 90                                      nop
                        .text:1002D26F 90                                      nop
                        .text:1002D270 90                                      nop
                        .text:1002D271 90                                      nop
                        .text:1002D272 90                                      nop
                        .text:1002D273 90                                      nop
                        .text:1002D274 90                                      nop
                        .text:1002D275 90                                      nop
                        .text:1002D276 90                                      nop
                        .text:1002D277 90                                      nop
                        .text:1002D278 90                                      nop
                        .text:1002D279 90                                      nop
                        .text:1002D27A 90                                      nop
                        .text:1002D27B 90                                      nop

                        '''

                        idc.PatchByte ( first_j       , 0xFF )
                        idc.PatchByte ( first_j + 0x1 , 0x15 )
                        idc.PatchDword( first_j + 0x2 , Dword( pos_3 + 0x2 ) )

                        # patch 0x90
                        patch_loop( first_j + 0x6, 2, 0x90)

                        # Patch from pos_2 8 bytes NOPS
                        patch_loop( pos_2, 8, 0x90)

                        # Copy push addr

                        idc.PatchByte( second_j, Byte( push_addr )) 
                        idc.PatchByte( second_j + 0x1, Byte( push_addr + 0x1 )) 
                        idc.PatchByte( second_j + 0x2, Byte( push_addr + 0x2 )) 
                        idc.PatchByte( second_j + 0x3, Byte( push_addr + 0x3 )) 
                        idc.PatchByte( second_j + 0x4, Byte( push_addr + 0x4 )) 

                        # Patch with ret
                        idc.PatchByte( second_j + 0x5, 0xC3 ) 

                        # Patch push_addr
                        patch_loop( push_addr, 5, 0x90)

                        idc.MakeCode(ea)
                        count_patched += 1


                    #If the final address first two bytes values are not FF 25 (jmp) 
                    else:

                        '''
                        .text:1002C85C 68 99 C8 02 10                          push    offset loc_1002C899
                        .text:1002C861 0F 84 B9 4C FD FF                       jz      loc_10001520
                        .text:1002C867 75 04                                   jnz     short loc_1002C86D
                        .text:1002C869 FD                                      std
                        .text:1002C86A 0A 00                                   or      al, [eax]
                        .text:1002C86C 00                                      db    0
                        .text:1002C86D
                        .text:1002C86D                         loc_1002C86D:                           
                        .text:1002C86D 0F 85 AD 4C FD FF                       jnz     loc_10001520
                        .text:1002C873 74 04                                   jz      short loc_1002C879
                        .text:1002C875 CF                                      iret

                        Patched:

                        .text:1002C85C 68 99 C8 02 10                          push    offset loc_1002C899
                        .text:1002C861 E9 BA 4C FD FF                          jmp     loc_10001520
                        .text:1002C861                         ; ---------------------------------------------------------------------------
                        .text:1002C866 FF                                      db 0FFh ; ÿ
                        .text:1002C867 75 04                                   jnz     short loc_1002C86D
                        .text:1002C869 FD                                      std
                        .text:1002C86A 0A 00                                   or      al, [eax]
                        .text:1002C86A                         ; ---------------------------------------------------------------------------
                        .text:1002C86C 00                                      db    0
                        .text:1002C86D                         ; ---------------------------------------------------------------------------
                        .text:1002C86D
                        .text:1002C86D                         loc_1002C86D:                           ; CODE XREF: .text:1002C867↑j
                        .text:1002C86D 90                                      nop
                        .text:1002C86E 90                                      nop
                        .text:1002C86F 90                                      nop
                        .text:1002C870 90                                      nop
                        .text:1002C871 90                                      nop
                        .text:1002C872 90                                      nop
                        .text:1002C873 90                                      nop
                        .text:1002C874 90                                      nop
                        '''

                        idc.PatchByte ( first_j       , 0xE9 )
                        idc.PatchDword( first_j + 0x1 , Dword(first_j + 0x2) + 0x1 )

                        # Patch from pos_2 8 bytes NOPS
                        patch_loop( pos_2, 8, 0x90)
                        idc.MakeCode(ea)
                        count_patched += 1

        print "Pattern: {0}".format(pattern)
        print "\tPatched obfuscated_jz_jnz_2: {0}".format(count_patched)
        print "\tNot Patched obfuscated_jz_jnz_2: {0}".format(count_not_patched)



#########################################################################################

def patch_loop(address, size, value):

    for i in range(0, size):

        idc.PatchByte(address + i, value) 


#########################################################################################


print "START SCRIPT"
print "=========================================="
print "MAZE DEOBFUSCATOR"
print "=========================================="
print "TASK[0] - find_and_rename_memcpy_function()"
find_and_rename_memcpy_function()

print "=========================================="
print "TASK[1] - delete_fake_calls_before_jz_jnz()"
delete_fake_calls_before_jz_jnz()

print "=========================================="
print "TASK[2] - obfuscated_jz_jnz()"
obfuscated_jz_jnz()

print "=========================================="
print "TASK[3] - patch_jmp_eax()"
patch_jmp_eax()

print "=========================================="
print "TASK[4] - obfuscated_jz_jnz_2()"
obfuscated_jz_jnz_2()

print "=========================================="
print "END SCRIPT"



