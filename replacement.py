import abc,idc, idautils, idaapi,ida_bytes,ida_search,sys

SIZE_OF_EGREGOR_TEXT_SECTION = 0x1b000

class Replacement():

    def __init__(self,patterns_list,segment=".text",verbose=False,in_mem=0):
        # in_mem should contain the adress of the .text section in memory. if set
        self.in_mem = in_mem
        self.patterns_list = patterns_list
        self.verbose = verbose
        self.address_list = []
        self.segment = segment
        self.init_segment_limits()

    def init_segment_limits(self):
        for i in idautils.Segments():
            if idc.get_segm_name(i) == self.segment:
                if self.in_mem:
                    self.start = self.in_mem
                    self.end = ( self.in_mem + SIZE_OF_EGREGOR_TEXT_SECTION )
                else:
                    self.start = idc.get_segm_start(i)
                    self.end = idc.get_segm_end(i)
        
        if not self.start or not self.end:
            raise Exception("Could not initialize code segment for patterns {}".format(self.patterns))

    def print_log(self,msg):
        if not self.verbose:
            return False
        print(msg)
        return True

    @abc.abstractmethod
    def replace_patterns(self):
        pass

    def is_in_code(self,ea):
        if self.in_mem:
            if ea > self.start and ea <  self.end:
                return True
            else:
                return False
        else:
            if self.segment == idc.get_segm_name(ea):
                return True
            return False

    def find_patterns(self): 
        count_address = 0
        temp_start = self.start
        SEARCH_DOWN = 1
        SEARCH_CASE = 4
        SEARCH_NEXT = 2
        for p in self.patterns_list:

            ea = 0

            while ea != idc.BADADDR:
                ea = ida_search.find_binary(temp_start, self.end,p ,16 ,SEARCH_DOWN|SEARCH_CASE | SEARCH_NEXT)
                self.print_log("found pattern {} in address {}".format(p,hex(ea)))
                
                # Advance start of search in order to not find the same pattern every time.
                temp_start = ea

                # if the pattern is within the code segment, add to the list
                if self.is_in_code(ea) and ea != idc.BADADDR:
                    self.address_list.append(ea)


    def patch_instructions(self,addr,instructions,size,nop=0x90):
        num_of_ops = len(instructions)
        for op,i in zip(instructions,range(num_of_ops)):
            ida_bytes.patch_byte(addr + i,instructions[i])

        for i in range(num_of_ops,size):
            ida_bytes.patch_byte(addr + i,nop)

    def replace(self):
        self.find_patterns()
        self.replace_patterns()