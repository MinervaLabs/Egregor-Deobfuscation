import idc, idautils, idaapi,ida_bytes,ida_search,sys
# add the relevant imports.


"""
what
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
