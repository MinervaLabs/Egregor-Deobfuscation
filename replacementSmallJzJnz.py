import idaapi,idc,ida_bytes,keystone

idaapi.require("replacement")

class ReplacementSmallJzJnz(replacement.Replacement):

    def __init__(self,**kwds):
        self.patterns_list = [ "74 ?? 75 ??", "75 ?? 74 ??"]
        super().__init__(self.patterns_list,**kwds)

    def replace_patterns(self):
        count_patched = 0
        for addr in self.address_list:
            j_1_pos    = addr
            j_1_value  = idc.get_wide_byte( j_1_pos + 0x1 )

            j_2_pos   = j_1_pos + 0x2
            j_2_value = idc.get_wide_byte( j_2_pos + 0x1 ) 

            
            if (j_1_value - j_2_value) == 0x2 or (j_1_value - j_2_value) == -0x2:

                # Patch the jz and jnz instructions with NOPs (12 bytes)

                # Patch with a relative jmp (size = 5) in the position of the second conditional jmp
                
                # handle sign bit of jmp if the jmp is to a negative location
                ins = ""
                byte_sign_flip = lambda x: (0x7f & x) - 128
                ins_str = idc.generate_disasm_line(addr,0)
                print(ins_str)
                diff_to_jump = addr
                if j_1_value < 0x80:
                    ins = "JMP {}".format(hex(j_1_value))
                else:
                    j_1_value = byte_sign_flip(j_1_value)
                    ins = "JMP {}".format(hex(j_1_value))
                #print("j_1_pos={}\tj_1_value={}".format(hex(j_1_pos),hex(j_1_value)))
                ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
                #print(ins)
                encoding, count = ks.asm(ins)
                pointer_in_code = 0
                #if j_1_value == 0x433248A:
                #print("{} = {}".format(ins,encoding))
                hex_opcodes = " ".join(list(map(lambda x: hex(x)[2:],encoding)))
                self.print_log("for address {} the pos_jmp is {}\tinstruction is {}\topcodes are {}".format(hex(addr),hex(j_1_value),ins,hex_opcodes))
                # TODO: fix byte patching it patches a single byte extra.
                ida_bytes.patch_byte(j_1_pos, 0xeb)
                ida_bytes.patch_byte(j_1_pos + 1, j_1_value)
                ida_bytes.patch_byte(j_1_pos + 2, 0x90)
                ida_bytes.patch_byte(j_1_pos + 3, 0x90)

                idc.create_insn(addr)
                idc.create_insn(j_1_pos + 2)

                count_patched += 1

        self.print_log("patched {} occurences of jz\jnz obfuscation".format(count_patched))
