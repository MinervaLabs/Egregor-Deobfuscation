import idc, idautils, idaapi,ida_bytes,ida_search,sys
# add the relevant imports.


"""
the plan:

go over code section, if you find  one of the above change it to its relevent alternative
jz x
jnz x
==
jmp x
nop * number of bytes left


push x
ret
==
jump x
nop * number of bytes left

push x
push y
ret
ret
==
jmp y
nop * number of bytes left


so what kind of functions and classes will i need?

i need a function that uses the find bytes in ida and finds all the occurences of the "bad" code.
def find_patterns(patterns_list):
    return address_list

i need a function that fixes tha address, although it needs to get as a function a specifiec fixing function.
def fix(address_list,fixing_func,verbose=False):
    fix the address using the function from the parameter.
    print stats and shit if verbose is true, for debugging.
    return stats_of_changes


the purpose of this code is to make my life very easy when staticly analysing obfuscated code.

a pattern could be a class, but what is the advantage of that? there is no advantage of that being a class that i can see right now.

def is_in_segment(segment):
    return True/False


there needs to be a logical connection in the log between a pattern and its fixing algorithm. i might want to initialize a class for each type of pattern
"""

idaapi.require("replacementBigJzJnz")
idaapi.require("replacementSmallJzJnz")
idaapi.require("replacementPushRetShort")
idaapi.require("replacementPushRetLong")

def main():
    replace_jzjnz_small = replacementSmallJzJnz.ReplacementSmallJzJnz()
    replace_jzjnz_small.replace()
    replace_pushret = replacementPushRetShort.ReplacementPushRetShort()
    replace_pushret.replace()
    replace_pushret = replacementPushRetLong.ReplacementPushRetLong()
    replace_pushret.replace()
    replace_jzjnz_big = replacementBigJzJnz.ReplacementBigJzJnz(verbose=True)
    replace_jzjnz_big.replace()


if __name__ == "__main__":
    main()