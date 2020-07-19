import idautils
import idaapi
import pefile
import idc
import sys
import traceback
import ctypes
import re
class Head(object):
    def __init__(self, *args):
        if len(args) == 1:
            idc.op_hex(args[0], 0)
            idc.op_hex(args[0], 1)
            op1 = idc.GetOpnd(args[0], 0)
            op2 = idc.GetOpnd(args[0], 1)
            if op1 == '':
                op1 = False
            if op2 == '':
                op2 = False
            self.ea = args[0]
            self.mnem = idc.GetMnem(args[0])
            self.op1 = op1
            self.op2 = op2
            self.extend = 0
        elif len(args) == 4:
            self.ea = args[0]
            self.mnem = args[1]
            self.op1 = args[2]
            self.op2 = args[3]
            self.extend = 0
        elif len(args) == 5:
            self.ea = args[0]
            self.mnem = args[1]
            self.op1 = args[2]
            self.op2 = args[3]
            self.extend = args[4]

def IsNumber2(str):
    try:
        val = int(str)
    except ValueError:
        return False
    return True
def IsNumber(str):
    try:
        if str[len(str)-1] == 'h':
            int(str[:len(str) - 1], 16)
        else:
            int(str, 16)
    except ValueError:
        return False
    return True
def hex2int(h):
    if h[len(h)-1] == 'h':
        return int(h[:len(h) - 1], 16)
    else:
        return int(h, 16)
def int2hex(v):
    if v > 10:
        if v < 16:
            return '0'+hex(v)[2:] + 'h'
        else:
            return hex(v)[2:] + 'h'
    else:
        return hex(v)[2:]
def GetSameRegister(op):
    if op == 'eax' or op == 'ax' or op == 'ah' or op == 'al':
        return ['eax', 'ax', 'ah', 'al']
    elif op == 'ebx' or op == 'bx' or op == 'bh' or op == 'bl':
        return ['ebx', 'bx', 'bh', 'bl']
    elif op == 'ecx' or op == 'cx' or op == 'ch' or op == 'cl':
        return ['ecx', 'cx', 'ch', 'cl']
    elif op == 'edx' or op == 'dx' or op == 'dh' or op == 'dl':
        return ['edx', 'dx', 'dh', 'dl']
    elif op == 'esp' or op == 'sp':
        return ['esp', 'sp']
    elif op == 'ebp' or op == 'bp':
        return ['ebp', 'bp']
    elif op == 'edi' or op == 'di':
        return ['edi', 'di']
    elif op == 'esi' or op == 'si':
        return ['esi', 'si']
def GetReferenceReg(op):
    if not op:
        return False
    a = op.find('[')
    if a == -1:
        return False
    a += 1
    b = op.find(']')
    return op[a:b]
def GetRegInfo(op):
    if not op:
        return False
    return re.split(r'([+-])+', op)
def IsRegsInOpEqualTarget(op, target):
    reference_reg = GetReferenceReg(op)
    if not reference_reg:
        return False
    t_info = GetRegInfo(reference_reg)
    reference_reg_info = []
    for info in t_info:
        if not info == '+' and not info == '-':
            reference_reg_info.append(info)
    for info in reference_reg_info:
        regs = GetSameRegister(info)
        for reg in regs:
            print reg
            if reg == target:
                return True
    return False
def LoadInstructions():
    result = []
    start_ea = False
    try:
        ins_load_file = open("C:\idalog\load_state.hs", 'rt')
        lines = ins_load_file.readlines()
        for line in lines:
            info = line.split('\t')
            size = len(info)
            if size == 3:
                mnem = info[0]
                op1 = info[1]
                op2 = info[2][:len(info[2]) - 1]
                result.append(Head(len(result), mnem, op1, op2))
            elif size == 1:
                start_ea = int(info[0][2:], 16)
        ins_load_file.close()
    except Exception, e:
        ins_load_file.close()
    return [result, start_ea]
#f = open('C:\Nexon\Maple\MapleStory.exe', 'rb+')
#ins_load_file = open("C:\idalog\load_state.hs", 'r+')
def step_until_ret():
    mnem = idc.GetMnem(idc.here())
    while not mnem == 'retn':
        idaapi.step_over()
        idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)
        mnem = idc.GetMnem(idc.here())
def step_until_ret_usage_run():
    mnem = idc.GetMnem(idc.here())
    while not mnem == 'retn':
        idaapi.step_until_ret()
        idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)
        mnem = idc.GetMnem(idc.here())
def SetAllConditionBpt():
    ea = 0x2C13000
    while ea < 0x357D000:
        mnem = idc.GetMnem(ea)
        if mnem == 'jmp' or mnem == 'retn':
            idc.add_bpt(ea)
        ea = idc.NextHead(ea)
def DelAllConditionBpt():
    ea = 0x2C13000
    while ea < 0x357D000:
        mnem = idc.GetMnem(ea)
        if mnem == 'jmp' or mnem == 'retn':
            idc.del_bpt(ea)
        ea = idc.NextHead(ea)
def AllChangeCode():
    ea = 0x2C13000
    while ea < 0x357D000:
        idc.MakeCode(ea)
        ea += 1
try:
    step_until_ret_usage_run()
    #step_until_ret()
except Exception, e:
    print 'ha'
    #f.close()
#idaapi.request_step_until_ret()
#idaapi.start_process()
'''seg = idaapi.get_segm_by_name('deob')
f = open('C:\Nexon\Maple\MapleStory.exe', 'rb+')
try:
    pe = pefile.PE(data=f.read(0x400))
    f.seek(0x3C63031)
    f.write(chr(0x67))
    f.write(chr(0x35))
    f.write(chr(0x84))
    f.write(chr(0x85))
    f.write(chr(0x86))
    print '0x%x' % f.tell()
    print '0x%x' % pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print '0x%x' % pe.OPTIONAL_HEADER.SectionAlignment
    for section in pe.sections:
        print '0x%x' % section.Misc_VirtualSize
        print '0x%x' % section.SizeOfRawData
        print 'virtual address : 0x%x , point to raw data : 0x%x' % (section.VirtualAddress, section.PointerToRawData)
    idaapi.assemble(0x3C6302C, 0, 0, True, 'mov dword ptr [ecx], esp') #push edi
    # idc.patch_dword(0x03c63063, 0x000067b8)
    print '%d' % idaapi.get_byte(0x3c63038)
    print '%d' % (0xFFFFFF80)
    f.close()
except Exception, e:
    print str(e)
    f.close()
    traceback.print_exc()
'''