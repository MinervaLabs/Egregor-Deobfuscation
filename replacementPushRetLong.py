import idaapi,idc,ida_bytes,keystone

idaapi.require("replacement")

class ReplacementPushRetLong(replacement.Replacement):

    def __init__(self,**kwds):
        self.patterns_list = ["68 ?? ?? ?? ?? 68 ?? ?? ?? ?? c3"]
        super().__init__(self.patterns_list,**kwds)

    def check_16or32_jump(self,ea,addr_to_jump):
        diff = addr_to_jump - ea
        print("diff = {} ".format(diff))
        if 0xffff > diff > 0xff:
            # this is 16 bit
            return 0

        #this is 32 bit.
        return True




    def replace_patterns(self):
        """
        i found a problem.
        there is a case of obfuscation that looks like this:
        .text:0433213B                 push    offset loc_4332152
        .text:04332140                 push    offset nullsub_2
        .text:04332145                 retn

        nullsub_2:
        ret

        this is what happens when the jump is not a short jump. my solution right now is to replace this pattern before this one with the following algo:

        search this pattern:
        push dword1
        push dword2
        ret

        then match if the code in dword2 is ret.

        replace with:
        jmp dword1 ; probably a 16\32 bit jmp might be problematic
        nop * 6
        """
        count_patched = 0
        size_of_pattern = 11
        # 0433213B is an example in egregor for this incident
        for addr in self.address_list:
            p_1_pos    = addr
            p_1_value  = idc.get_wide_dword( p_1_pos + 0x1 )
            
            p_2_pos = p_1_pos + 0x5
            p_2_value = idc.get_wide_dword(p_2_pos + 0x1)

            opcode_at_first_jmp = idc.get_wide_byte(p_2_value)
            if opcode_at_first_jmp in [0xc3,0xcb]:
                
                byte_sign_flip = lambda x: (0x7f & x) - 128
                word_sign_flip = lambda x: (0x7fff & x) - 0x8000
                dword_sign_flip =  lambda x: (0x7fffffff & x ) - 0x80000000
                diff = p_1_value - addr
                self.print_log("Diff = {}\tAddress of first instructuin = {}\t".format(hex(diff), hex(addr)))
                # if the diff is a byte size use short jump 0x80 till -0x80
                ins = "JMP {}".format(diff)
                ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
                encoding, count = ks.asm(ins)
                self.patch_instructions(addr,encoding,size_of_pattern)
                idc.create_insn(addr)
                idc.create_insn(addr + len(encoding))
                count_patched += 1


        self.print_log("patched {} occurences of push ret obfuscation".format(count_patched))
