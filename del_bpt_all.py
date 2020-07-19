import idaapi
import idc
def DelAllConditionBpt():
    ea = 0x2C13000
    while ea < 0x357D000:
        mnem = idc.GetMnem(ea)
        if mnem == 'jmp' or mnem == 'retn':
            idc.DelBpt(ea)
        ea = idc.NextHead(ea)

DelAllConditionBpt()