import idaapi,idc,ida_bytes,keystone

idaapi.require("replacement")

class ReplacementPushRetShort(replacement.Replacement):

    def __init__(self,**kwds):
        self.patterns_list = ["68 ?? ?? ?? ?? c3", "68 ?? ?? ?? ?? cb"]
        super().__init__(self.patterns_list,**kwds)

    def check_short_jump(self,ea,addr_to_jump):
        diff = addr_to_jump - ea
        print("diff = {} ".format(diff))
        if diff > 0xff:
            return 0

        return diff


    def replace_patterns(self):
        """
        This has to be executed after the long push ret.
        """
        count_patched = 0
        size_of_pattern = 6
        for addr in self.address_list:
            p_1_pos    = addr
            p_1_value  = idc.get_wide_dword( p_1_pos + 0x1 )
            ins = ""
            byte_sign_flip = lambda x: (0x7f & x) - 128
            diff = p_1_value - addr
            self.print_log("Diff = {}\tAddress of first instructuin = {}\t".format(hex(diff), hex(addr)))
            # if the diff is a byte size use short jump 0x80 till -0x80
            ins = "JMP {}".format(hex(diff))
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
            encoding, count = ks.asm(ins)
            hex_opcodes = " ".join(list(map(lambda x: hex(x)[2:],encoding)))
            self.print_log("In address {} the instruction {} was patched with the following bytes {}. The original jump was to address {}".format(hex(addr),ins,hex_opcodes,hex(p_1_value)))
            self.patch_instructions(addr,encoding,size_of_pattern)

            # this is wrong for this case fix this.
            idc.create_insn(addr)
            idc.create_insn(addr + len(encoding))

            count_patched += 1

        self.print_log("patched {} occurences of push ret obfuscation".format(count_patched))
