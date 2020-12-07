import idaapi,idc,ida_bytes,keystone,struct,ida_ua

idaapi.require("replacement")

class ReplacementBigJzJnz(replacement.Replacement):

    def __init__(self,**kwds):
        self.patterns_list = ["0F 84 ?? ?? ?? ?? 0F 85 ?? ?? ?? ??", "0F 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ??"]
        super().__init__(self.patterns_list,**kwds)

    def replace_patterns(self):
        count_patched = 0
        size_of_pattern = 12
        for addr in self.address_list:
            j_1_pos    = addr
            j_1_value  = idc.get_wide_dword( j_1_pos + 0x2 )

            j_2_pos   = j_1_pos + 0x6
            j_2_value = idc.get_wide_dword( j_2_pos + 0x2 ) 

            pos_jmp = j_1_pos + j_1_value + 0x6
            
            if (j_1_value - j_2_value) == 0x6 or (j_1_value - j_2_value) == -0x6:

                # Patch the jz and jnz instructions with NOPs (12 bytes)

                # Patch with a relative jmp (size = 5) in the position of the second conditional jmp
                #jz      loc_4331122
                if j_1_value > -0x80 and j_1_value < 0x80:
                    size_of_instruction = 2
                    addr_to_jmp = j_1_value + size_of_instruction
                    ins = "JMP {}".format(addr_to_jmp)
                    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
                    encoding, count = ks.asm(ins)
                    hex_opcodes = " ".join(list(map(lambda x: hex(x)[2:],encoding)))
                    self.print_log("this is byte jump. for address {} the pos_jmp is {}; the opcodes are {}".format(hex(addr),hex(j_1_value),hex_opcodes))
                    self.patch_instructions(addr,encoding,size_of_pattern)
                    # ida_bytes.patch_byte(j_1_pos, 0xeb)
                    # ida_bytes.patch_byte(j_1_pos + 1, j_1_value)
                    # ida_bytes.patch_byte(j_1_pos + 2, 0x90)
                    # ida_bytes.patch_byte(j_1_pos + 3, 0x90)
                    idc.create_insn(addr)
                    idc.create_insn(j_1_pos + 2)
                    count_patched += 1
                else:
                    # print("in address {} The jump value is {} ".format(hex(addr),hex(j_1_value)))
                    # idc.patch_byte(j_1_pos,0xe9)
                    # idc.patch_dword(j_1_pos+1,j_1_value)
                    # remaining_bytes_offset = j_1_pos + 0x5
                    # for i in range(size_of_pattern - 5):
                    #     idc.patch_byte(remaining_bytes_offset + i,0x90)
                    size_of_instruction = 6
                    addr_to_jmp = j_1_value + size_of_instruction
                    ins = "JMP {}".format(addr_to_jmp)
                    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
                    encoding, count = ks.asm(ins)
                    hex_opcodes = " ".join(list(map(lambda x: hex(x)[2:],encoding)))
                    self.print_log("this is [d]word jump. for address {} the pos_jmp is {} ; the opcodes are {}".format(hex(addr),hex(j_1_value),hex_opcodes))
                    self.patch_instructions(addr,encoding,size_of_pattern)
                    idc.create_insn(addr)
                    idc.create_insn(j_1_pos + 5)

                    count_patched += 1

        self.print_log("patched {} occurences of jz\jnz obfuscation".format(count_patched))
# this should be good 0433239A