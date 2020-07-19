import idaapi
import idc
def SetAllConditionBpt():
    ea = 0x2C13000
    while ea < 0x357D000:
        mnem = idc.GetMnem(ea)
        if mnem == 'jmp' or mnem == 'retn':
            idc.AddBpt(ea)
        ea = idc.NextHead(ea)

SetAllConditionBpt()