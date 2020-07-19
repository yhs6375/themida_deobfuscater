import sys
sys.path.append('C:\python27-x64\Lib\site-packages')

import idautils
import pefile
import idc
import inspect
import idaapi
import re
import traceback
import ctypes

JumpList=['jmp', 'jb', 'jbe', 'jz', 'jnz', 'jno', 'jle', 'jo', 'jnp', 'jg', 'jp', 'jnb', 'jl', 'jns', 'jge', 'ja']

class Head(object):
    def __init__(self, *args):
        if len(args) == 1:
            idaapi.op_hex(args[0], 0)
            idaapi.op_hex(args[0], 1)
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

# first loop deob functions
def jump_deob():
    global force_jmp_ea, isInsert, zero_flag, status_check_conditional_jmp, force_stop, new_ins_list, waiting_jmp_ea
    if not cur.mnem == 'jmp' and IsOpEqual(cur.op1, '$+6'):
        curHeadRemove()
    elif cur.mnem == 'jmp' and IsOpEqual(cur.op1, '$+5'):
        curHeadRemove()
    else:
        if StrFind(cur.op1, 'near ptr unk'):
            cur.op1 = 'loc' + cur.op1[12:]
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s\n' % (cur.ea, cur.extend, cur.mnem, cur.op1))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s\n' % (cur.ea, cur.mnem, cur.op1))
        elif StrFind(cur.op1, 'near ptr dword'):
            info = GetRegInfo(cur.op1[15:])
            if len(info) == 1:
                cur.op1 = 'loc_' + info[0]
            elif len(info) == 3:
                offset = False
                if info[1] == '+':
                    offset = int(info[0], 16) + int(info[2], 16)
                elif info[1] == '-':
                    offset = int(info[0], 16) - int(info[2], 16)
                cur.op1 = 'loc_%s' % int2hex(offset)
                print cur.op1
        if cur.mnem == 'jmp':
            value = GetJmpValue(cur.op1)
            if value:
                curHeadRemove()
                force_jmp_ea = value
            else:
                op1_value = False
                op1_reference_reg = GetReferenceReg(cur.op1)
                if op1_reference_reg:
                    t_val = GetRegValue(op1_reference_reg)
                    if not t_val == -1:
                        op1_value = GetOffsetDwordValueIfCan(t_val)
                else:
                    t_len = len(new_ins_list) - 1
                    while not t_len == 0:
                        head = new_ins_list[t_len]
                        if not head:
                            break
                        if head.extend:
                            print_log('\tjmp op1 check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                        else:
                            print_log('\tjmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                        if head.mnem == 'mov':
                            if IsOpEqual(head.op1, cur.op1):
                                if IsNumber(head.op2):
                                    op1_value = hex2int(head.op2)
                                    break
                                else:
                                    op2_reference_reg = GetReferenceReg(head.op2)
                                    if op2_reference_reg:
                                        if IsNumber(op2_reference_reg):
                                            op1_value = GetOffsetDwordValueIfCan(op2_reference_reg)
                                    break
                        elif head.mnem == 'movzx':
                            if IsOpEqual(head.op1, cur.op1):
                                break
                        elif IsCalcMnem(head.mnem):
                            if IsOpEqual(head.op1, cur.op1):
                                break
                        elif head.mnem == 'pop':
                            if IsOpEqual(head.op1, cur.op1):
                                break
                        t_len -= 1
                if isinstance(op1_value, long):
                    print_log('op1_value : 0x%x\n' % op1_value)
                else:
                    print_log('op1_value : %s\n' % op1_value)
                if not op1_value == -1 and op1_value is not False:
                    curHeadRemove()
                    force_jmp_ea = op1_value
                    waiting_jmp_ea = False
                else:
                    force_stop = True
                    if not waiting_jmp_ea:
                        waiting_jmp_ea = cur.ea
                    print_log('\twaiting_jmp_ea : 0x%x\n' % waiting_jmp_ea)
        elif cur.mnem == 'jz':
            if status_check_conditional_jmp:
                condition_head_index = len(new_ins_list) - 1
                condition_head = new_ins_list[condition_head_index]
                if condition_head.mnem == 'cmp' or IsCalcMnem(condition_head.mnem):
                    op1_value = -1
                    op2_value = -1
                    search_reg = condition_head.op1
                    if IsLowBitRegister(search_reg):
                        search_reg = GetTopRegister(search_reg)
                    t_len2 = condition_head_index - 1
                    while not t_len2 == 0:
                        head = new_ins_list[t_len2]
                        if not head:
                            break
                        if head.extend:
                            print_log('\tcmp op1 check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                        else:
                            print_log('\tcmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                        if head.mnem == 'mov':
                            if IsOpEqual(head.op1, search_reg):
                                if IsNumber(head.op2):
                                    op1_value = hex2int(head.op2)
                                    break
                                else:
                                    op1_reference_reg = GetReferenceReg(head.op2)
                                    if op1_reference_reg:
                                        if IsNumber(op1_reference_reg):
                                            op1_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                                    break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'movzx':
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif IsCalcMnem(head.mnem):
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'pop':
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'xchg':
                            if IsOpEqual(head.op1, search_reg) or IsLowBitSameRegister(head.op1, search_reg):
                                break
                            elif IsOpEqual(head.op2, search_reg) or IsLowBitSameRegister(head.op1, search_reg):
                                break
                        t_len2 -= 1
                    if not op1_value == -1:
                        if IsWordRegister(condition_head.op1):
                            op1_value &= 0xFFFF
                        elif IsLowHighRegister(condition_head.op1):
                            op1_value &= 0xFF00
                        elif IsLowLowRegister(condition_head.op1):
                            op1_value &= 0xFF
                    print_log('\t\tcondition_head op1 : 0x%x\n' % op1_value)
                    if not op1_value == -1:
                        if IsNumber(condition_head.op2):
                            op2_value = hex2int(condition_head.op2)
                        else:
                            search_reg = condition_head.op2
                            if IsLowBitRegister(search_reg):
                                search_reg = GetTopRegister(search_reg)
                            t_len2 = condition_head_index - 1
                            while not t_len2 == 0:
                                head = new_ins_list[t_len2]
                                if not head:
                                    break
                                if head.extend:
                                    print_log(
                                        '\tcmp op1 check loop(0x%x(%d)) : %s\n' % (
                                        head.ea, head.extend, GetDisasm(head)))
                                else:
                                    print_log('\tcmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                                if head.mnem == 'mov':
                                    if IsOpEqual(head.op1, search_reg):
                                        if IsNumber(head.op2):
                                            op2_value = hex2int(head.op2)
                                            break
                                        else:
                                            op2_reference_reg = GetReferenceReg(head.op2)
                                            if op2_reference_reg:
                                                if IsNumber(op2_reference_reg):
                                                    op2_value = GetOffsetDwordValueIfCan(op2_reference_reg)
                                            break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif head.mnem == 'movzx':
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif IsCalcMnem(head.mnem):
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif head.mnem == 'pop':
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                t_len2 -= 1
                            if not op2_value == -1:
                                if IsWordRegister(condition_head.op2):
                                    op2_value &= 0xFFFF
                                elif IsLowHighRegister(condition_head.op2):
                                    op2_value &= 0xFF00
                                elif IsLowLowRegister(condition_head.op2):
                                    op2_value &= 0xFF
                    print_log('\t\tcondition_head op2 : 0x%x\n' % op2_value)
                    if not op1_value == -1 and not op2_value == -1:
                        curHeadRemove()
                        new_ins_list.pop(condition_head_index)
                        print_log('\t\t(0x%x) index remove\n' % condition_head_index)
                        condition_success = False
                        result = 0
                        if condition_head.mnem == 'sub' or condition_head.mnem == 'cmp':
                            result = unsigned32(op1_value - op2_value)
                        elif condition_head.mnem == 'add':
                            result = unsigned32(op1_value + op2_value)
                        elif condition_head.mnem == 'xor':
                            result = unsigned32(op1_value ^ op2_value)
                        elif condition_head.mnem == 'and':
                            result = unsigned32(op1_value & op2_value)
                        elif condition_head.mnem == 'or':
                            result = unsigned32(op1_value | op2_value)
                        elif condition_head.mnem == 'shr':
                            result = unsigned32(op1_value >> op2_value)
                        elif condition_head.mnem == 'shl':
                            result = unsigned32(op1_value << op2_value)
                        if result == 0:
                            force_jmp_ea = GetJmpValue(cur.op1)
                            print 'force_jmp : 0x%x' % force_jmp_ea
                        else:
                            if cur.ea < 0x400000:
                                force_jmp_ea = NextHead(waiting_jmp_ea).ea
                            else:
                                force_jmp_ea = NextHead(cur.ea).ea
                        waiting_jmp_ea = False
                    else:
                        force_stop = True
                        if not waiting_jmp_ea:
                            waiting_jmp_ea = cur.ea
                        print_log('\twaiting_jmp_ea : 0x%x\n' % waiting_jmp_ea)
                else:
                    curHeadRemove()
                    force_jmp_ea = GetJmpValue(cur.op1)
            else:
                curHeadRemove()
                force_jmp_ea = GetJmpValue(cur.op1)
        elif cur.mnem == 'jnz':
            if status_check_conditional_jmp:
                condition_head_index = len(new_ins_list) - 1
                condition_head = new_ins_list[condition_head_index]
                if condition_head.mnem == 'cmp':
                    op1_value = -1
                    op2_value = -1
                    search_reg = condition_head.op1
                    if IsLowBitRegister(search_reg):
                        search_reg = GetTopRegister(search_reg)
                    t_len2 = condition_head_index - 1
                    while not t_len2 == 0:
                        head = new_ins_list[t_len2]
                        if not head:
                            break
                        if head.extend:
                            print_log('\tcmp op1 check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                        else:
                            print_log('\tcmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                        if head.mnem == 'mov':
                            if IsOpEqual(head.op1, search_reg):
                                if IsNumber(head.op2):
                                    op1_value = hex2int(head.op2)
                                    break
                                else:
                                    op1_reference_reg = GetReferenceReg(head.op2)
                                    if op1_reference_reg:
                                        if IsNumber(op1_reference_reg):
                                            op1_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                                    break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'movzx':
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif IsCalcMnem(head.mnem):
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'pop':
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'xchg':
                            if IsOpEqual(head.op1, search_reg) or IsLowBitSameRegister(head.op1, search_reg):
                                break
                            elif IsOpEqual(head.op2, search_reg) or IsLowBitSameRegister(head.op1, search_reg):
                                break
                        t_len2 -= 1
                    if not op1_value == -1:
                        if IsWordRegister(condition_head.op1):
                            op1_value &= 0xFFFF
                        elif IsLowHighRegister(condition_head.op1):
                            op1_value &= 0xFF00
                        elif IsLowLowRegister(condition_head.op1):
                            op1_value &= 0xFF
                    print_log('\t\tcmp op1 : 0x%x\n' % op1_value)
                    if not op1_value == -1:
                        if IsNumber(condition_head.op2):
                            op2_value = hex2int(condition_head.op2)
                        else:
                            search_reg = condition_head.op2
                            if IsLowBitRegister(search_reg):
                                search_reg = GetTopRegister(search_reg)
                            t_len2 = condition_head_index - 1
                            while not t_len2 == 0:
                                head = new_ins_list[t_len2]
                                if not head:
                                    break
                                if head.extend:
                                    print_log(
                                        '\tcmp op1 check loop(0x%x(%d)) : %s\n' % (
                                        head.ea, head.extend, GetDisasm(head)))
                                else:
                                    print_log('\tcmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                                if head.mnem == 'mov':
                                    if IsOpEqual(head.op1, search_reg):
                                        if IsNumber(head.op2):
                                            op2_value = hex2int(head.op2)
                                            break
                                        else:
                                            op2_reference_reg = GetReferenceReg(head.op2)
                                            if op2_reference_reg:
                                                if IsNumber(op2_reference_reg):
                                                    op2_value = GetOffsetDwordValueIfCan(op2_reference_reg)
                                            break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif head.mnem == 'movzx':
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif IsCalcMnem(head.mnem):
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif head.mnem == 'pop':
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                t_len2 -= 1
                            if not op2_value == -1:
                                if IsWordRegister(condition_head.op2):
                                    op2_value &= 0xFFFF
                                elif IsLowHighRegister(condition_head.op2):
                                    op2_value &= 0xFF00
                                elif IsLowLowRegister(condition_head.op2):
                                    op2_value &= 0xFF
                    print_log('\t\tcmp op2 : 0x%x\n' % op2_value)
                    if not op1_value == -1 and not op2_value == -1:
                        curHeadRemove()
                        new_ins_list.pop(condition_head_index)
                        print_log('\t\t(0x%x) index remove\n' % condition_head_index)
                        if not op1_value == op2_value:
                            force_jmp_ea = GetJmpValue(cur.op1)
                            print 'force_jmp : 0x%x' % force_jmp_ea
                        else:
                            if cur.ea < 0x400000:
                                force_jmp_ea = NextHead(waiting_jmp_ea).ea
                            else:
                                force_jmp_ea = NextHead(cur.ea).ea
                        waiting_jmp_ea = False
                    else:
                        force_stop = True
                        if not waiting_jmp_ea:
                            waiting_jmp_ea = cur.ea
                        print_log('\twaiting_jmp_ea : 0x%x\n' % waiting_jmp_ea)
                else:
                    curHeadRemove()
                    force_jmp_ea = idc.GetOperandValue(cur.ea, 0)
            else:
                curHeadRemove()
                force_jmp_ea = idc.GetOperandValue(cur.ea, 0)
        elif cur.mnem == 'jbe':
            if status_check_conditional_jmp:
                condition_head_index = len(new_ins_list) - 1
                condition_head = new_ins_list[condition_head_index]
                if condition_head.mnem == 'cmp':
                    op1_value = -1
                    op2_value = -1
                    search_reg = condition_head.op1
                    if IsLowBitRegister(search_reg):
                        search_reg = GetTopRegister(search_reg)
                    t_len2 = condition_head_index - 1
                    while not t_len2 == 0:
                        head = new_ins_list[t_len2]
                        if not head:
                            break
                        if head.extend:
                            print_log('\tcmp op1 check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                        else:
                            print_log('\tcmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                        if head.mnem == 'mov':
                            if IsOpEqual(head.op1, search_reg):
                                if IsNumber(head.op2):
                                    op1_value = hex2int(head.op2)
                                    break
                                else:
                                    op1_reference_reg = GetReferenceReg(head.op2)
                                    if op1_reference_reg:
                                        if IsNumber(op1_reference_reg):
                                            op1_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                                    break
                            elif IsOpEqual(head.op1, condition_head.op1):
                                if IsNumber(head.op2):
                                    op1_value = hex2int(head.op2)
                                    break
                                else:
                                    op1_reference_reg = GetReferenceReg(head.op2)
                                    if op1_reference_reg:
                                        if IsNumber(op1_reference_reg):
                                            op1_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                                    break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'movzx':
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif IsCalcMnem(head.mnem):
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'pop':
                            if IsOpEqual(head.op1, search_reg):
                                break
                            elif IsLowBitSameRegister(head.op1, search_reg):
                                break
                        elif head.mnem == 'xchg':
                            if IsOpEqual(head.op1, search_reg) or IsLowBitSameRegister(head.op1, search_reg):
                                break
                            elif IsOpEqual(head.op2, search_reg) or IsLowBitSameRegister(head.op1, search_reg):
                                break
                        t_len2 -= 1
                    if not op1_value == -1:
                        if IsWordRegister(condition_head.op1):
                            op1_value &= 0xFFFF
                        elif IsLowHighRegister(condition_head.op1):
                            op1_value &= 0xFF00
                        elif IsLowLowRegister(condition_head.op1):
                            op1_value &= 0xFF
                    print_log('\t\tcmp op1 : 0x%x\n' % op1_value)
                    if not op1_value == -1:
                        if IsNumber(condition_head.op2):
                            op2_value = hex2int(condition_head.op2)
                        else:
                            search_reg = condition_head.op2
                            if IsLowBitRegister(search_reg):
                                search_reg = GetTopRegister(search_reg)
                            t_len2 = condition_head_index - 1
                            while not t_len2 == 0:
                                head = new_ins_list[t_len2]
                                if not head:
                                    break
                                if head.extend:
                                    print_log(
                                        '\tcmp op1 check loop(0x%x(%d)) : %s\n' % (
                                        head.ea, head.extend, GetDisasm(head)))
                                else:
                                    print_log('\tcmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                                if head.mnem == 'mov':
                                    if IsOpEqual(head.op1, search_reg):
                                        if IsNumber(head.op2):
                                            op2_value = hex2int(head.op2)
                                            break
                                        else:
                                            op2_reference_reg = GetReferenceReg(head.op2)
                                            if op2_reference_reg:
                                                if IsNumber(op2_reference_reg):
                                                    op2_value = GetOffsetDwordValueIfCan(op2_reference_reg)
                                            break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif head.mnem == 'movzx':
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif IsCalcMnem(head.mnem):
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                elif head.mnem == 'pop':
                                    if IsOpEqual(head.op1, search_reg):
                                        break
                                    elif IsLowBitSameRegister(head.op1, search_reg):
                                        break
                                t_len2 -= 1
                            if not op2_value == -1:
                                if IsWordRegister(condition_head.op2):
                                    op2_value &= 0xFFFF
                                elif IsLowHighRegister(condition_head.op2):
                                    op2_value &= 0xFF00
                                elif IsLowLowRegister(condition_head.op2):
                                    op2_value &= 0xFF
                    print_log('\t\tcmp op2 : 0x%x\n' % op2_value)
                    if not op1_value == -1 and not op2_value == -1:
                        curHeadRemove()
                        new_ins_list.pop(condition_head_index)
                        print_log('\t\t(0x%x) index remove\n' % condition_head_index)
                        if op1_value <= op2_value:
                            force_jmp_ea = GetJmpValue(cur.op1)
                            print 'force_jmp : 0x%x' % force_jmp_ea
                        else:
                            if cur.ea < 0x400000:
                                force_jmp_ea = NextHead(waiting_jmp_ea).ea
                            else:
                                force_jmp_ea = NextHead(cur.ea).ea
                        waiting_jmp_ea = False
                    else:
                        force_stop = True
                        if not waiting_jmp_ea:
                            waiting_jmp_ea = cur.ea
                        print_log('\twaiting_jmp_ea : 0x%x\n' % waiting_jmp_ea)
                else:
                    curHeadRemove()
                    force_jmp_ea = idc.GetOperandValue(cur.ea, 0)
            else:
                curHeadRemove()
                force_jmp_ea = idc.GetOperandValue(cur.ea, 0)
        else:
            if not status_check_conditional_jmp:
                force_jmp_ea = idc.GetOperandValue(cur.ea, 0)
                curHeadRemove()
            elif status_check_conditional_jmp and GetJmpValue(cur.op1):
                force_jmp_ea = idc.GetOperandValue(cur.ea, 0)
                curHeadRemove()
            else:
                print 'error!!!!'

def push_deob():
    global modifyList, except_list                                           # base global variable
    global push_count, isContinue, head2, traceList         # first global variable
    global isExchanged, exchangeTarget, exchange_ea, last_target_op_change  # first global variable
    global org_push_reg_mnem, can_push_pop_remove, can_stack_change_check
    global push_pattern1_modify_list, push_mov_late_except_list, isExchangeEncounter, isPopMemoryEspEncounter, is_op1_used
    global once_stack_change_register_encounter, push_pop_late_modify_list
    global last_target_push_count, reserve_esp_modify_list, is_cur_op1_known_value, is_cur_target_reg_changed
    global cur_target_reg, is_cur_target_reg_point_reg_changed, cur_target_reg_point_reg, is_cur_target_reg_known_value
    global cur_stack_calc_list, is_cur_stack_changed, is_cur_stack_used, esp_size_change_late_extend_list
    op1_reference_reg = GetReferenceReg(cur.op1)
    if op1_reference_reg and not StrFind(op1_reference_reg, 'esp'):
        if not IsNumber(op1_reference_reg):
            reference_offset = GetRegValue(op1_reference_reg)
            if not reference_offset == -1:
                t_value = GetOffsetDwordValueIfCan(reference_offset)
                if t_value == -1:
                    if IsOpWord(cur.op1):
                        cur.op1 = 'word ptr [%s]' % reference_offset
                    elif IsOpByte(cur.op1):
                        cur.op1 = 'byte ptr [%s]' % reference_offset
                    else:
                        cur.op1 = 'dword ptr [%s]' % reference_offset
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1))
                    else:
                        print_log('\t\tcurrent target change(0x%x) : %s %s\n' % (cur.ea, cur.mnem, cur.op1))
                else:
                    cur.op1 = int2hex(t_value)
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1))
                    else:
                        print_log('\t\tcurrent target change(0x%x) : %s %s\n' % (cur.ea, cur.mnem, cur.op1))
    op1_reference_reg = GetReferenceReg(cur.op1)
    traceList = [[cur.ea, cur.extend]]
    push_count = 0
    head2 = cur
    last_target_op_change = []
    last_target_push_count = 0
    isExchanged=False
    isExchangeEncounter = False
    isPopMemoryEspEncounter = False
    org_push_reg_mnem = ''
    can_push_pop_remove=True
    can_stack_change_check = True
    once_stack_change_register_encounter = False
    push_pattern1_modify_list = []
    push_mov_late_except_list = []
    push_pop_late_modify_list = []
    esp_size_change_late_extend_list = []
    reserve_esp_modify_list = []
    is_cur_op1_known_value = True
    is_cur_stack_changed = False
    is_cur_target_reg_changed = False
    is_op1_used = False
    cur_target_reg = cur.op1
    cur_stack_calc_list = []
    cur_target_reg_point_reg = False
    is_cur_target_reg_point_reg_changed = False
    is_cur_target_reg_known_value = True
    is_cur_stack_used = False
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            isContinue = False
            break
        if not IsHeadinExceptList(head2):
            if IsJump(head2.mnem):
                break
            elif head2.mnem == 'retn':
                break
            if head2.extend:
                print_log('\tpush first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
            else:
                print_log('\tpush first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
            traceList.append([head2.ea,head2.extend])
            if IsPushMnem(head2.mnem):
                push_push_deob()
            elif head2.mnem == 'pop':
                push_pop_deob()
            elif head2.mnem == 'mov':
                push_mov_deob()
            elif head2.mnem == 'movzx':
                push_movzx_deob()
            elif IsCalcMnem(head2.mnem):
                push_calc_deob()
            elif head2.mnem == 'xchg':
                push_xchg_deob()
def pop_deob():
    global cur, new_ins_list, head2, isContinue
    op1_reference_reg = GetReferenceReg(cur.op1)
    if op1_reference_reg and not StrFind(op1_reference_reg, 'esp'):
        if not IsNumber(op1_reference_reg):
            reference_offset = GetRegValue(op1_reference_reg)
            if not reference_offset == -1:
                if IsOpWord(cur.op1):
                    cur.op1 = 'word ptr [%s]' % reference_offset
                elif IsOpByte(cur.op1):
                    cur.op1 = 'byte ptr [%s]' % reference_offset
                else:
                    cur.op1 = 'dword ptr [%s]' % reference_offset
                if cur.extend:
                    print_log('\t\tcurrent target change(0x%x(%d)) : %s %s\n' % (
                        cur.ea, cur.extend, cur.mnem, cur.op1))
                else:
                    print_log('\t\tcurrent target change(0x%x) : %s %s\n' % (cur.ea, cur.mnem, cur.op1))
    is_not_number_offset_ref_used_insert_op = False
    is_not_number_offset_ref_used_op = False
    head2 = cur
    isContinue = True
    if op1_reference_reg and not IsNumber(op1_reference_reg):
        isContinue = False
    elif StrFind(cur.op1, '[esp'):
        isContinue = False
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            break
        if not IsHeadinExceptList(head2):
            if IsJump(head2.mnem):
                break
            elif head2.mnem == 'retn':
                break
            if head2.extend:
                print_log('\tpop mnem first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
            else:
                print_log('\tpop mnem first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
            head2_op1_reference_reg = GetReferenceReg(head2.op1)
            head2_op2_reference_reg = GetReferenceReg(head2.op2)
            if IsPushMnem(head2.mnem):
                if IsOpEqual(head2.op1, cur.op1):
                    break
                elif StrFind(head2.op1, cur.op1):
                    break
                elif IsLowBitSameRegister(head2.op1, cur.op1):
                    break
            elif head2.mnem == 'mov':
                if IsOpEqual(head2.op2, cur.op1):
                    break
                elif StrFind(head2.op2, cur.op1):
                    break
                elif IsLowBitSameRegister(head2.op1, cur.op1):
                    break
                elif IsLowBitSameRegister(head2.op2, cur.op1):
                    break
                elif IsOpInReferenceReg(head2.op1, cur.op1):
                    break
                if IsOpEqual(head2.op1, cur.op1):
                    cur.mnem = 'add'
                    cur.op1 = 'esp'
                    cur.op2 = '4'
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                    else:
                        print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
                    break
                if head2_op1_reference_reg:
                    if not IsNumber(head2_op1_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
                if head2_op2_reference_reg:
                    if not IsNumber(head2_op2_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
            elif head2.mnem == 'movzx':
                if IsOpEqual(head2.op2, cur.op1):
                    break
                elif StrFind(head2.op2, cur.op1):
                    break
                elif IsLowBitSameRegister(head2.op1, cur.op1):
                    break
                elif IsLowBitSameRegister(head2.op2, cur.op1):
                    break
                elif IsOpInReferenceReg(head2.op1, cur.op1):
                    break
                if IsOpEqual(head2.op1, cur.op1):
                    cur.mnem = 'add'
                    cur.op1 = 'esp'
                    cur.op2 = '4'
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                    else:
                        print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
                    break
                if head2_op1_reference_reg:
                    if not IsNumber(head2_op1_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
                if head2_op2_reference_reg:
                    if not IsNumber(head2_op2_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
            elif IsCalcMnem(head2.mnem):
                if IsOpEqual(head2.op1, cur.op1):
                    break
                elif StrFind(head2.op1, cur.op1):
                    break
                elif IsLowBitSameRegister(head2.op1, cur.op1):
                    break
                elif IsOpEqual(head2.op2, cur.op1):
                    break
                elif StrFind(head2.op2, cur.op1):
                    break
                elif IsLowBitSameRegister(head2.op2, cur.op1):
                    break
                if head2_op1_reference_reg:
                    if not IsNumber(head2_op1_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
                if head2_op2_reference_reg:
                    if not IsNumber(head2_op2_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
            elif head2.mnem == 'pop':
                if IsOpEqual(head2.op1, cur.op1):
                    cur.mnem = 'add'
                    cur.op1 = 'esp'
                    cur.op2 = '4'
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                    else:
                        print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
                    break
                if head2_op1_reference_reg and not IsNumber(head2_op1_reference_reg):
                    if not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
            elif head2.mnem == 'xchg':
                if IsOpEqual(head2.op1, cur.op1) or IsOpEqual(head2.op2, cur.op1):
                    break
                elif StrFind(head2.op1, cur.op1) or StrFind(head2.op2, cur.op1):
                    break
def calc_deob():
    global cur, head2, isContinue
    global test_record, deob_count
    is_cur_op1_low_bit_reg = False
    top_reg = False
    is_op1_stack_pointer = False
    compare_str = False
    push_count = 0
    op1_reference_reg = GetReferenceReg(cur.op1)
    if op1_reference_reg and not IsNumber(op1_reference_reg) and not StrFind(op1_reference_reg, 'esp'):
        reference_offset = GetRegValue(op1_reference_reg)
        if not reference_offset == -1:
            if IsWordRegister(cur.op2):
                if not IsOpWord(cur.op1):
                    cur.op1 = 'word ptr %s' % cur.op1
            elif IsLowHighRegister(cur.op2) or IsLowLowRegister(cur.op2):
                if not IsOpByte(cur.op1):
                    cur.op1 = 'byte ptr %s' % cur.op1
            if IsOpWord(cur.op1):
                cur.op1 = 'word ptr [%s]' % (reference_offset)
            elif IsOpByte(cur.op1):
                cur.op1 = 'byte ptr [%s]' % (reference_offset)
            else:
                cur.op1 = 'dword ptr [%s]' % reference_offset
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
    if cur.op2 is not False:
        op2_reference_reg = GetReferenceReg(cur.op2)
        if op2_reference_reg and not StrFind(op2_reference_reg, 'esp'):
            if IsNumber(op2_reference_reg):
                value = GetOffsetDwordValueIfCan(op2_reference_reg)
                if not value == -1:
                    cur.op2 = int2hex(value)
                    op2_reference_reg = False
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                    else:
                        print_log(
                            '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
        elif not op2_reference_reg and not IsNumber(cur.op2):
            value = GetRegValue(cur.op2)
            if not value == -1:
                if IsOpWord(cur.op2):
                    value = hex2int(value)
                    cur.op2 = int2hex(value & 0xFFFF)
                elif IsOpByte(cur.op2):
                    value = hex2int(value)
                    cur.op2 = int2hex(value & 0xFF)
                else:
                    cur.op2 = value
                if cur.extend:
                    print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                        cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                else:
                    print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                        cur.ea, cur.mnem, cur.op1, cur.op2))
    op1_reference_reg = GetReferenceReg(cur.op1)
    if (IsNeedOp2CalcMnem(cur.mnem) and IsNumber(cur.op2)) or IsSingleCalcMnem(cur.mnem):
        changed = False
        if op1_reference_reg:
            if IsNumber(op1_reference_reg):
                can_change = False
                offset_range = 0
                if IsOpWord(cur.op1):
                    op1_referenced_value = GetOffsetWordValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 1
                elif IsOpByte(cur.op1):
                    op1_referenced_value = GetOffsetByteValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 0
                else:
                    op1_referenced_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 3
                if can_change:
                    op1_referenced_dword_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                    if not op1_referenced_dword_value == -1:
                        if IsOpWord(cur.op1):
                            op1_referenced_word_value = GetOffsetWordValue(op1_reference_reg)
                            t_val1 = calc(cur.mnem, op1_referenced_word_value, cur.op2) & 0xFFFF
                            t_val2 = op1_referenced_dword_value & 0xFFFF0000
                            cur.op2 = int2hex(t_val1 + t_val2)
                        elif IsOpByte(cur.op1):
                            op1_referenced_byte_value = GetOffsetByteValue(op1_reference_reg)
                            t_val1 = calc(cur.mnem, op1_referenced_byte_value, cur.op2) & 0xFF
                            t_val2 = op1_referenced_dword_value & 0xFFFFFF00
                            cur.op2 = int2hex(t_val1 + t_val2)
                        else:
                            cur.op2 = int2hex(calc(cur.mnem, op1_referenced_dword_value, cur.op2))
                        cur.mnem = 'mov'
                        cur.op1 = 'dword ptr [%s]' % op1_reference_reg
                        if cur.extend:
                            print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                                cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                        else:
                            print_log(
                                '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
                        changed = True
                        isContinue = False
                    else:
                        can_change = False
                        change_head = False
                        change_head_offset = False
                        offset_int = hex2int(op1_reference_reg)
                        t_len = len(new_ins_list) - 1
                        while t_len >= 0:
                            head = new_ins_list[t_len]
                            if not head:
                                break
                            if head.extend:
                                print_log('\tcan offset value change check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                            else:
                                print_log('\tcan offset value change check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                            head_op1_reference_reg = GetReferenceReg(head.op1)
                            head_op2_reference_reg = GetReferenceReg(head.op2)
                            head_op1_reference_reg_int = False
                            head_op2_reference_reg_int = False
                            if head_op1_reference_reg:
                                if IsNumber(head_op1_reference_reg):
                                    head_op1_reference_reg_int = hex2int(head_op1_reference_reg)
                            if head_op2_reference_reg:
                                if IsNumber(head_op2_reference_reg):
                                    head_op2_reference_reg_int = hex2int(head_op2_reference_reg)
                            if head_op2_reference_reg_int:
                                if offset_int <= head_op2_reference_reg_int+3 and offset_int >= head_op2_reference_reg_int - offset_range:
                                    can_change = False
                                    break
                            if head.mnem == 'push':
                                if offset_int <= head_op1_reference_reg_int+3 and offset_int >= head_op1_reference_reg_int - offset_range:
                                    can_change = False
                                    break
                            elif head.mnem == 'mov':
                                if offset_int <= (head_op1_reference_reg_int+3-offset_range) and offset_int >= head_op1_reference_reg_int:
                                    change_head = head
                                    change_head_offset = head_op1_reference_reg_int
                                    can_change = True
                                    break
                            t_len -= 1
                        if can_change:
                            test_record.append([deob_count, cur.ea])
                            change = False
                            if change_head_offset == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFFFF00
                                    num2 = hex2int(change_head.op2) & 0xFF
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFFFF0000
                                    num2 = hex2int(change_head.op2) & 0xFFFF
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 3:
                                    change_head.op2 = int2hex(calc(cur.mnem, change_head.op2, cur.op2))
                                    change = True
                            elif change_head_offset+1 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFF00FF
                                    num2 = hex2int(change_head.op2) & 0xFF00
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFF0000FF
                                    num2 = hex2int(change_head.op2) & 0xFFFF00
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            elif change_head_offset+2 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFF00FFFF
                                    num2 = hex2int(change_head.op2) & 0xFF0000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFFFF
                                    num2 = hex2int(change_head.op2) & 0xFFFF0000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            elif change_head_offset+3 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFFFF
                                    num2 = hex2int(change_head.op2) & 0xFF000000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            if change:
                                curHeadRemove()
                                isContinue = False
                                print_log('\t\t\tchange new_ins_list(0x%x) : %s %s, %s\n' % (
                                change_head.ea, change_head.mnem, change_head.op1, change_head.op2))
        if not changed:
            isContinue = True
    else:
        isContinue = True
    if StrFind(cur.op1, '[esp'):
        is_op1_stack_pointer = True
        num = GetEspNumber(cur.op1) / 4
        if num > 0 or num == 0:
            push_count = num
        else:
            isContinue = False
    if IsLowBitRegister(cur.op1):
        is_cur_op1_low_bit_reg = True
        top_reg = GetTopRegister(cur.op1)
    else:
        top_reg = cur.op1
    head2 = cur
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            break
        if not IsHeadinExceptList(head2):
            if IsJump(head2.mnem):
                break
            if head2.extend:
                print_log('\tcalc mnem first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
            else:
                print_log('\tcalc mnem first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
            if is_op1_stack_pointer:
                compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
            if IsPushMnem(head2.mnem):
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        break
                else:
                    if IsOpEqual(head2.op1, top_reg):
                        break
                    elif IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                        break
                    elif IsLowBitSameRegister(head2.op1, top_reg):
                        break
            elif head2.mnem == 'mov':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        curHeadRemove()
                        break
                    elif IsOpEqual(head2.op2, compare_str):
                        break
                else:
                    if IsOpEqual(head2.op2, top_reg):
                        break
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            curHeadRemove()
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            break
                    else:
                        if IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                            break
                        elif IsOpInReferenceRegIncludeSameReg(head2.op2, cur.op1):
                            break
                        elif IsLowBitSameRegister(head2.op2, top_reg):
                            break
                        if IsOpEqual(head2.op1, cur.op1):
                            curHeadRemove()
                            break
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            break
                        elif IsOpEqual(head2.op1, top_reg):
                            curHeadRemove()
                            break
            elif head2.mnem == 'movzx':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        curHeadRemove()
                        break
                    elif IsOpEqual(head2.op2, compare_str):
                        break
                else:
                    if IsOpEqual(head2.op2, top_reg):
                        break
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            curHeadRemove()
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            break
                    else:
                        if IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                            break
                        elif IsOpInReferenceRegIncludeSameReg(head2.op2, cur.op1):
                            break
                        elif IsLowBitSameRegister(head2.op2, top_reg):
                            break
                        if IsOpEqual(head2.op1, cur.op1):
                            curHeadRemove()
                            break
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            break
                        elif IsOpEqual(head2.op1, top_reg):
                            curHeadRemove()
                            break
            elif IsCalcMnem(head2.mnem):
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        break
                    elif IsOpEqual(head2.op2, compare_str):
                        break
                    if head2.op1 == 'esp':
                        if head2.mnem == 'add':
                            if IsNumber(head2.op2):
                                count = hex2int(head2.op2) / 4
                                push_count -= count
                            else:
                                break
                        elif head2.mnem == 'sub':
                            if IsNumber(head2.op2):
                                count = hex2int(head2.op2) / 4
                                push_count += count
                            else:
                                break
                        else:
                            break
                else:
                    if cur.mnem == 'or':
                        if IsNumber(cur.op2):
                            t_num1 = hex2int(cur.op2)
                            if head2.mnem == 'and' and IsOpEqual(head2.op1, cur.op1) and IsNumber(head2.op2):
                                t_num2 = hex2int(head2.op2)
                                if t_num1 == t_num2:
                                    curHeadRemove()
                                    addHeadinModifyList(head2.ea, head2.extend, 'mov', cur.op1, cur.op2)
                                    break
                    if IsOpEqual(head2.op2, top_reg):
                        break
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            break
                    else:
                        if IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                            break
                        elif IsOpInReferenceRegIncludeSameReg(head2.op2, cur.op1):
                            break
                        elif IsLowBitSameRegister(head2.op2, top_reg):
                            break
                        if IsOpEqual(head2.op1, cur.op1):
                            break
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            break
                        elif IsOpEqual(head2.op1, top_reg):
                            break
            elif head2.mnem == 'pop':
                if op1_reference_reg:
                    if IsOpEqual(head2.op1, cur.op1):
                        curHeadRemove()
                        break
                    elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                        break
                else:
                    if IsOpEqual(head2.op1, cur.op1):
                        curHeadRemove()
                        break
                    elif IsOpEqual(head2.op1, top_reg):
                        curHeadRemove()
                        break
                    elif IsLowBitSameRegister(head2.op1, top_reg):
                        break
                push_count -= 1
            elif head2.mnem == 'xchg':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str) or IsOpEqual(head2.op2, compare_str):
                        break
                    elif IsOpEqual(head2.op1, cur.op2) or IsOpEqual(head2.op2, cur.op2):
                        break
                else:
                    if IsOpEqual(head2.op1, cur.op1) or IsOpEqual(head2.op2, cur.op1):
                        break
                    elif IsOpEqual(head2.op1, cur.op2) or IsOpEqual(head2.op2, cur.op2):
                        break
def addsub_deob():
    global cur, except_list, isInsert, new_ins_list
    global isContinue, saveValue, head2, is_op1_used
    global test_record, deob_count
    is_cur_op1_low_bit_reg = False
    top_reg = False
    is_op1_stack_pointer = False
    op1_reference_reg = GetReferenceReg(cur.op1)
    if op1_reference_reg and not IsNumber(op1_reference_reg) and not StrFind(op1_reference_reg, 'esp'):
        reference_offset = GetRegValue(op1_reference_reg)
        if not reference_offset == -1:
            if IsWordRegister(cur.op2):
                if not IsOpWord(cur.op1):
                    cur.op1 = 'word ptr %s' % cur.op1
            elif IsLowHighRegister(cur.op2) or IsLowLowRegister(cur.op2):
                if not IsOpByte(cur.op1):
                    cur.op1 = 'byte ptr %s' % cur.op1
            if IsOpWord(cur.op1):
                cur.op1 = 'word ptr [%s]' % (reference_offset)
            elif IsOpByte(cur.op1):
                cur.op1 = 'byte ptr [%s]' % (reference_offset)
            else:
                cur.op1 = 'dword ptr [%s]' % reference_offset
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
    is_op1_used = False
    is_op2_identify_real_value = True
    push_count = 0
    push_count2 = 0
    compare_str = False
    op2_reference_reg = GetReferenceReg(cur.op2)
    if op2_reference_reg and not StrFind(op2_reference_reg, 'esp'):
        if IsNumber(op2_reference_reg):
            value = GetOffsetDwordValueIfCan(op2_reference_reg)
            if not value == -1:
                cur.op2 = int2hex(value)
                op2_reference_reg = False
                if cur.extend:
                    print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                else:
                    print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
    elif not op2_reference_reg and not IsNumber(cur.op2):
        value = GetRegValue(cur.op2)
        if not value == -1:
            if IsOpWord(cur.op2):
                value = hex2int(value)
                cur.op2 = int2hex(value & 0xFFFF)
            elif IsOpByte(cur.op2):
                value = hex2int(value)
                cur.op2 = int2hex(value & 0xFF)
            else:
                cur.op2 = value
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                    cur.ea, cur.mnem, cur.op1, cur.op2))
    op1_reference_reg = GetReferenceReg(cur.op1)
    if IsNumber(cur.op2):
        changed = False
        if op1_reference_reg:
            if IsNumber(op1_reference_reg):
                can_change = False
                offset_range = 0
                if IsOpWord(cur.op1):
                    op1_referenced_value = GetOffsetWordValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 1
                elif IsOpByte(cur.op1):
                    op1_referenced_value = GetOffsetByteValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 0
                else:
                    op1_referenced_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 3
                if can_change:
                    op1_referenced_dword_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                    if not op1_referenced_dword_value == -1:
                        if IsOpWord(cur.op1):
                            op1_referenced_word_value = GetOffsetWordValue(op1_reference_reg)
                            t_val1 = calc(cur.mnem, op1_referenced_word_value, cur.op2) & 0xFFFF
                            t_val2 = op1_referenced_dword_value & 0xFFFF0000
                            cur.op2 = int2hex(t_val1 + t_val2)
                        elif IsOpByte(cur.op1):
                            op1_referenced_byte_value = GetOffsetByteValue(op1_reference_reg)
                            t_val1 = calc(cur.mnem, op1_referenced_byte_value, cur.op2) & 0xFF
                            t_val2 = op1_referenced_dword_value & 0xFFFFFF00
                            cur.op2 = int2hex(t_val1 + t_val2)
                        else:
                            cur.op2 = int2hex(calc(cur.mnem, op1_referenced_dword_value, cur.op2))
                        cur.mnem = 'mov'
                        cur.op1 = 'dword ptr [%s]' % op1_reference_reg
                        if cur.extend:
                            print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                                cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                        else:
                            print_log(
                                '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
                        changed = True
                        isContinue = False
                    else:
                        can_change = False
                        change_head = False
                        change_head_offset = False
                        offset_int = hex2int(op1_reference_reg)
                        t_len = len(new_ins_list) - 1
                        while t_len >= 0:
                            head = new_ins_list[t_len]
                            if not head:
                                break
                            if head.extend:
                                print_log('\tcan offset value change check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                            else:
                                print_log('\tcan offset value change check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                            head_op1_reference_reg = GetReferenceReg(head.op1)
                            head_op2_reference_reg = GetReferenceReg(head.op2)
                            head_op1_reference_reg_int = False
                            head_op2_reference_reg_int = False
                            if head_op1_reference_reg:
                                if IsNumber(head_op1_reference_reg):
                                    head_op1_reference_reg_int = hex2int(head_op1_reference_reg)
                            if head_op2_reference_reg:
                                if IsNumber(head_op2_reference_reg):
                                    head_op2_reference_reg_int = hex2int(head_op2_reference_reg)
                            if head_op2_reference_reg_int:
                                if offset_int <= head_op2_reference_reg_int+3 and offset_int >= head_op2_reference_reg_int - offset_range:
                                    can_change = False
                                    break
                            if head.mnem == 'push':
                                if offset_int <= head_op1_reference_reg_int+3 and offset_int >= head_op1_reference_reg_int - offset_range:
                                    can_change = False
                                    break
                            elif head.mnem == 'mov':
                                if offset_int <= (head_op1_reference_reg_int+3-offset_range) and offset_int >= head_op1_reference_reg_int:
                                    change_head = head
                                    change_head_offset = head_op1_reference_reg_int
                                    can_change = True
                                    break
                            t_len -= 1
                        if can_change:
                            test_record.append([deob_count, cur.ea])
                            change = False
                            if change_head_offset == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFFFF00
                                    num2 = hex2int(change_head.op2) & 0xFF
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFFFF0000
                                    num2 = hex2int(change_head.op2) & 0xFFFF
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 3:
                                    change_head.op2 = int2hex(calc(cur.mnem, change_head.op2, cur.op2))
                                    change = True
                            elif change_head_offset+1 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFF00FF
                                    num2 = hex2int(change_head.op2) & 0xFF00
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFF0000FF
                                    num2 = hex2int(change_head.op2) & 0xFFFF00
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            elif change_head_offset+2 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFF00FFFF
                                    num2 = hex2int(change_head.op2) & 0xFF0000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFFFF
                                    num2 = hex2int(change_head.op2) & 0xFFFF0000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            elif change_head_offset+3 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFFFF
                                    num2 = hex2int(change_head.op2) & 0xFF000000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            if change:
                                curHeadRemove()
                                isContinue = False
                                print_log('\t\t\tchange new_ins_list(0x%x) : %s %s, %s\n' % (change_head.ea, change_head.mnem, change_head.op1, change_head.op2))
        if not changed:
            saveValue = unsigned32(hex2int(cur.op2))
            isContinue = True
            head2 = cur
    else:
        is_op2_identify_real_value = False
        saveValue = False
        head2 = cur
        isContinue = True

    if isContinue:
        if cur.mnem == 'add' and cur.op1 == 'esp' and IsNumber(cur.op2):
            stack_size = hex2int(cur.op2)
            if stack_size > 4:
                cur.op2 = '4'
                stack_size -= 4
                while stack_size > 0:
                    addExtendHeadinHead(cur.ea, 'add', 'esp', '4')
                    stack_size -= 4
    if StrFind(cur.op1, '[esp'):
        is_op1_stack_pointer = True
        num = GetEspNumber(cur.op1) / 4
        if num > 0 or num == 0:
            push_count2 = num
        else:
            isContinue = False
    if IsLowBitRegister(cur.op1):
        is_cur_op1_low_bit_reg = True
        top_reg = GetTopRegister(cur.op1)
    else:
        top_reg = cur.op1
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            break
        if not IsHeadinExceptList(head2):
            if IsJump(head2.mnem):
                break
            if head2.extend:
                print_log('\taddsub first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
            else:
                print_log('\taddsub first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
            if is_op1_stack_pointer:
                compare_str = (push_count2 > 0 and '[esp+%s' % int2hex(push_count2 * 4) + ']' or '[esp]')
                print_log('\t\tcompare_str : %s\n' % compare_str)
                if IsOpEqual(head2.op2, compare_str):
                    is_op1_used = True
            else:
                if IsOpEqual(head2.op2, top_reg):
                    is_op1_used = True
                elif IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                    is_op1_used = True
                elif IsOpInReferenceRegIncludeSameReg(head2.op2, cur.op1):
                    is_op1_used = True
                elif IsLowBitSameRegister(head2.op2, top_reg):
                    is_op1_used = True
            if head2.mnem == 'add':
                if head2.op1 == 'esp':
                    count = GetEspNumber(head2.op2) / 4
                    push_count -= count
                    push_count2 -= count
                if is_op1_stack_pointer:
                    if IsNumber(head2.op2) and not is_op1_used and is_op2_identify_real_value:
                        if IsOpEqual(head2.op1, compare_str):
                            if cur.mnem == 'add':  # add eax, 1055856221 / add eax, 1833880101
                                saveValue += unsigned32(hex2int(head2.op2))
                                cur.op2 = int2hex(unsigned32(saveValue))
                            elif cur.mnem == 'sub':  # sub eax, 1055856221 / add eax, 1833880101
                                saveValue -= unsigned32(hex2int(head2.op2))
                                if saveValue < 0:
                                    cur.mnem = 'add'
                                    saveValue = unsigned32((~saveValue) + 1)
                                    cur.op2 = int2hex(saveValue)
                                elif saveValue == 0:
                                    curHeadRemove()
                                    isContinue = False
                                else:
                                    cur.op2 = int2hex(unsigned32(saveValue))
                            if isInsert:
                                print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
                            addHeadinExceptList(head2)
                    else:
                        if IsOpEqual(head2.op1, compare_str):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                else:
                    if IsNumber(head2.op2) and not is_op1_used and is_op2_identify_real_value:
                        if IsOpEqual(head2.op1, cur.op1):
                            check1 = True
                            if cur.mnem == 'add':  # add eax, 1055856221 / add eax, 1833880101
                                if not IsOpEqual(cur.op1, 'esp'):
                                    saveValue += unsigned32(hex2int(head2.op2))
                                    cur.op2 = int2hex(unsigned32(saveValue))
                                else:
                                    check1 = False
                            elif cur.mnem == 'sub':  # sub eax, 1055856221 / add eax, 1833880101
                                saveValue -= unsigned32(hex2int(head2.op2))
                                if saveValue < 0:
                                    cur.mnem = 'add'
                                    saveValue = unsigned32((~saveValue) + 1)
                                    cur.op2 = int2hex(saveValue)
                                elif saveValue == 0:
                                    curHeadRemove()
                                    isContinue = False
                                else:
                                    cur.op2 = int2hex(unsigned32(saveValue))
                            if check1:
                                if isInsert:
                                    print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
                                addHeadinExceptList(head2)
                        elif IsLowBitSameRegister(head2.op1, cur.op1):
                            is_op2_identify_real_value = False
                    else:
                        if op1_reference_reg:
                            if IsOpEqual(head2.op1, cur.op1):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
                            elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
                        else:
                            if IsOpEqual(head2.op1, cur.op1):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
                            elif IsLowBitSameRegister(head2.op1, top_reg):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
                            elif IsOpEqual(head2.op1, top_reg):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
            elif head2.mnem == 'sub':
                if head2.op1 == 'esp':
                    count = hex2int(head2.op2) / 4
                    push_count += count
                    push_count2 += count
                if is_op1_stack_pointer:
                    if IsNumber(head2.op2) and not is_op1_used and is_op2_identify_real_value:
                        if IsOpEqual(head2.op1, compare_str):
                            if cur.mnem == 'add':  # add eax, 1055856221 / sub eax, 1833880101
                                saveValue -= unsigned32(hex2int(head2.op2))
                                if saveValue < 0:
                                    cur.mnem = 'sub'
                                    saveValue = unsigned32((~saveValue) + 1)
                                    cur.op2 = int2hex(saveValue)
                                elif saveValue == 0:
                                    curHeadRemove()
                                    isContinue = False
                                else:
                                    cur.op2 = int2hex(unsigned32(saveValue))
                            elif cur.mnem == 'sub':  # sub eax, 1055856221 / sub eax, 1833880101
                                saveValue += unsigned32(hex2int(head2.op2))
                                cur.op2 = int2hex(unsigned32(saveValue))
                            if isInsert:
                                print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
                            addHeadinExceptList(head2)
                    else:
                        if IsOpEqual(head2.op1, compare_str):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                else:
                    if IsNumber(head2.op2) and not is_op1_used and not IsOpEqual(cur.op1, 'esp') and is_op2_identify_real_value:
                        if IsOpEqual(head2.op1, cur.op1):
                            if cur.mnem == 'add':  # add eax, 1055856221 / sub eax, 1833880101
                                saveValue -= unsigned32(hex2int(head2.op2))
                                if saveValue < 0:
                                    cur.mnem = 'sub'
                                    saveValue = unsigned32((~saveValue) + 1)
                                    cur.op2 = int2hex(saveValue)
                                elif saveValue == 0:
                                    curHeadRemove()
                                    isContinue = False
                                else:
                                    cur.op2 = int2hex(unsigned32(saveValue))
                            elif cur.mnem == 'sub':  # sub eax, 1055856221 / sub eax, 1833880101
                                if not IsOpEqual(cur.op1, 'esp'):
                                    saveValue += unsigned32(hex2int(head2.op2))
                                    cur.op2 = int2hex(unsigned32(saveValue))
                            if isInsert:
                                print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
                            addHeadinExceptList(head2)
                        elif IsLowBitSameRegister(head2.op1, cur.op1):
                            is_op2_identify_real_value = False
                    else:
                        if op1_reference_reg:
                            if IsOpEqual(head2.op1, cur.op1):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
                            elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
                        else:
                            if IsOpEqual(head2.op1, cur.op1):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
                            elif IsLowBitSameRegister(head2.op1, top_reg):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
                            elif IsOpEqual(head2.op1, top_reg):
                                if is_op1_used:
                                    break
                                is_op2_identify_real_value = False
            elif head2.mnem == 'or' or head2.mnem == 'xor' or head2.mnem == 'and' \
                    or head2.mnem == 'shr' or head2.mnem == 'shl' or head2.mnem == 'not' \
                    or head2.mnem == 'dec' or head2.mnem == 'inc':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        if is_op1_used:
                            break
                        is_op2_identify_real_value = False
                else:
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                    else:
                        if IsOpEqual(head2.op1, cur.op1):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                        elif IsOpEqual(head2.op1, top_reg):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
            elif IsPushMnem(head2.mnem):
                if cur.op1 == 'esp':
                    break
                elif StrFind(cur.op1, '[esp'):
                    break
                elif IsOpEqual(head2.op1, cur.op1):
                    is_op1_used = True
                elif IsLowBitSameRegister(head2.op1, cur.op1):
                    is_op1_used = True
                else:
                    push_count += 1
                push_count2 += 1
            elif head2.mnem == 'pop':
                if cur.op1 == 'esp':
                    break
                elif StrFind(cur.op1, '[esp'):
                    break
                else:
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            if not is_op1_used:
                                curHeadRemove()
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                    else:
                        if IsOpEqual(head2.op1, cur.op1):
                            if not is_op1_used:
                                curHeadRemove()
                            break
                        elif IsLowBitSameRegister(head2.op1, cur.op1):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                        elif IsOpEqual(head2.op1, top_reg):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                    push_count -= 1
                push_count2 -= 1
            elif head2.mnem == 'mov':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        if not is_op1_used:
                            curHeadRemove()
                        break
                else:
                    if cur.mnem == 'sub':
                        compare_str2 = push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]'
                        print_log('\t\tmov compare_str : %s\n' % compare_str2)
                        if cur.op1 == 'esp' and is_op2_identify_real_value and saveValue == 4 and IsOpEqual(head2.op1, compare_str2):
                            if head2.op2 == 'esp':
                                cur.mnem = 'push'
                                cur.op1 = head2.op2
                                cur.op2 = False
                                if cur.extend:
                                    print_log('\t\tcurrent target change (0x%x(%d)) : %s %s\n' % (
                                    cur.ea, cur.extend, cur.mnem, cur.op1))
                                else:
                                    print_log(
                                        '\t\tcurrent target change (0x%x) : %s %s\n' % (cur.ea, cur.mnem, cur.op1))
                                addExtendHeadinHead(cur.ea, 'sub', '[esp]', int2hex((push_count + 1) * 4))
                                addHeadinExceptList(head2)
                            else:
                                curHeadRemove()
                                addHeadinModifyList(head2.ea, head2.extend, 'push', head2.op2, False)
                            break
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            if not is_op1_used:
                                curHeadRemove()
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                    else:
                        if IsOpEqual(head2.op1, cur.op1):
                            if not is_op1_used:
                                curHeadRemove()
                            break
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                        elif IsOpEqual(head2.op1, top_reg):
                            if not is_op1_used:
                                curHeadRemove()
                            break
            elif head2.mnem == 'movzx':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        if not is_op1_used:
                            curHeadRemove()
                        break
                else:
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            if not is_op1_used:
                                curHeadRemove()
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                    else:
                        if IsOpEqual(head2.op1, cur.op1):
                            if not is_op1_used:
                                curHeadRemove()
                            break
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            if is_op1_used:
                                break
                            is_op2_identify_real_value = False
                        elif IsOpEqual(head2.op1, top_reg):
                            if not is_op1_used:
                                curHeadRemove()
                            break
            elif head2.mnem == 'xchg':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str) or IsOpEqual(head2.op2, compare_str):
                        break
                    elif IsOpEqual(head2.op1, cur.op2) or IsOpEqual(head2.op2, cur.op2):
                        break
                else:
                    if IsOpEqual(head2.op1, cur.op1) or IsOpEqual(head2.op2, cur.op1):
                        break
                    elif IsOpEqual(head2.op1, cur.op2) or IsOpEqual(head2.op2, cur.op2):
                        break
def xor_deob():
    global except_list, isInsert, cur, new_ins_list, zero_flag
    global isContinue, head2
    is_cur_op1_low_bit_reg = False
    top_reg = False
    is_op1_stack_pointer = False
    push_count = 0
    op1_reference_reg = GetReferenceReg(cur.op1)
    if op1_reference_reg and not IsNumber(op1_reference_reg) and not StrFind(op1_reference_reg, 'esp'):
        reference_offset = GetRegValue(op1_reference_reg)
        if not reference_offset == -1:
            if IsWordRegister(cur.op2):
                if not IsOpWord(cur.op1):
                    cur.op1 = 'word ptr %s' % cur.op1
            elif IsLowHighRegister(cur.op2) or IsLowLowRegister(cur.op2):
                if not IsOpByte(cur.op1):
                    cur.op1 = 'byte ptr %s' % cur.op1
            if IsOpWord(cur.op1):
                cur.op1 = 'word ptr [%s]' % (reference_offset)
            elif IsOpByte(cur.op1):
                cur.op1 = 'byte ptr [%s]' % (reference_offset)
            else:
                cur.op1 = 'dword ptr [%s]' % reference_offset
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
    op2_reference_reg = GetReferenceReg(cur.op2)
    if op2_reference_reg and not StrFind(op2_reference_reg, 'esp'):
        if IsNumber(op2_reference_reg):
            value = GetOffsetDwordValueIfCan(op2_reference_reg)
            if not value == -1:
                cur.op2 = int2hex(value)
                op2_reference_reg = False
                if cur.extend:
                    print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                        cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                else:
                    print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
    elif not op2_reference_reg and not IsNumber(cur.op2):
        value = GetRegValue(cur.op2)
        if not value == -1:
            if IsOpWord(cur.op2):
                value = hex2int(value)
                cur.op2 = int2hex(value & 0xFFFF)
            elif IsOpByte(cur.op2):
                value = hex2int(value)
                cur.op2 = int2hex(value & 0xFF)
            else:
                cur.op2 = value
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                    cur.ea, cur.mnem, cur.op1, cur.op2))
    op1_reference_reg = GetReferenceReg(cur.op1)
    if IsNumber(cur.op2):
        changed = False
        if op1_reference_reg:
            if IsNumber(op1_reference_reg):
                can_change = False
                offset_range = 0
                if IsOpWord(cur.op1):
                    op1_referenced_value = GetOffsetWordValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 1
                elif IsOpByte(cur.op1):
                    op1_referenced_value = GetOffsetByteValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 0
                else:
                    op1_referenced_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                    if not op1_referenced_value == -1:
                        can_change = True
                        offset_range = 3
                if can_change:
                    op1_referenced_dword_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                    if not op1_referenced_dword_value == -1:
                        if IsOpWord(cur.op1):
                            op1_referenced_word_value = GetOffsetWordValue(op1_reference_reg)
                            t_val1 = calc(cur.mnem, op1_referenced_word_value, cur.op2) & 0xFFFF
                            t_val2 = op1_referenced_dword_value & 0xFFFF0000
                            cur.op2 = int2hex(t_val1 + t_val2)
                        elif IsOpByte(cur.op1):
                            op1_referenced_byte_value = GetOffsetByteValue(op1_reference_reg)
                            t_val1 = calc(cur.mnem, op1_referenced_byte_value, cur.op2) & 0xFF
                            t_val2 = op1_referenced_dword_value & 0xFFFFFF00
                            cur.op2 = int2hex(t_val1 + t_val2)
                        else:
                            cur.op2 = int2hex(calc(cur.mnem, op1_referenced_dword_value, cur.op2))
                        cur.mnem = 'mov'
                        cur.op1 = 'dword ptr [%s]' % op1_reference_reg
                        if cur.extend:
                            print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                                cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                        else:
                            print_log(
                                '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
                        changed = True
                        isContinue = False
                    else:
                        can_change = False
                        change_head = False
                        change_head_offset = False
                        offset_int = hex2int(op1_reference_reg)
                        t_len = len(new_ins_list) - 1
                        while t_len >= 0:
                            head = new_ins_list[t_len]
                            if not head:
                                break
                            if head.extend:
                                print_log('\tcan offset value change check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                            else:
                                print_log('\tcan offset value change check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                            head_op1_reference_reg = GetReferenceReg(head.op1)
                            head_op2_reference_reg = GetReferenceReg(head.op2)
                            head_op1_reference_reg_int = False
                            head_op2_reference_reg_int = False
                            if head_op1_reference_reg:
                                if IsNumber(head_op1_reference_reg):
                                    head_op1_reference_reg_int = hex2int(head_op1_reference_reg)
                            if head_op2_reference_reg:
                                if IsNumber(head_op2_reference_reg):
                                    head_op2_reference_reg_int = hex2int(head_op2_reference_reg)
                            if head_op2_reference_reg_int:
                                if offset_int <= head_op2_reference_reg_int+3 and offset_int >= head_op2_reference_reg_int - offset_range:
                                    can_change = False
                                    break
                            if head.mnem == 'push':
                                if offset_int <= head_op1_reference_reg_int+3 and offset_int >= head_op1_reference_reg_int - offset_range:
                                    can_change = False
                                    break
                            elif head.mnem == 'mov':
                                if offset_int <= (head_op1_reference_reg_int+3-offset_range) and offset_int >= head_op1_reference_reg_int:
                                    change_head = head
                                    change_head_offset = head_op1_reference_reg_int
                                    can_change = True
                                    break
                            t_len -= 1
                        if can_change:
                            test_record.append([deob_count, cur.ea])
                            change = False
                            if change_head_offset == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFFFF00
                                    num2 = hex2int(change_head.op2) & 0xFF
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFFFF0000
                                    num2 = hex2int(change_head.op2) & 0xFFFF
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 3:
                                    change_head.op2 = int2hex(calc(cur.mnem, change_head.op2, cur.op2))
                                    change = True
                            elif change_head_offset+1 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFF00FF
                                    num2 = hex2int(change_head.op2) & 0xFF00
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFF0000FF
                                    num2 = hex2int(change_head.op2) & 0xFFFF00
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            elif change_head_offset+2 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFF00FFFF
                                    num2 = hex2int(change_head.op2) & 0xFF0000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                                elif offset_range == 1:
                                    num1 = hex2int(change_head.op2) & 0xFFFF
                                    num2 = hex2int(change_head.op2) & 0xFFFF0000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            elif change_head_offset+3 == offset_int:
                                if offset_range == 0:
                                    num1 = hex2int(change_head.op2) & 0xFFFFFF
                                    num2 = hex2int(change_head.op2) & 0xFF000000
                                    change_head.op2 = int2hex(num1 + calc(cur.mnem, num2, cur.op2))
                                    change = True
                            if change:
                                curHeadRemove()
                                isContinue = False
                                print_log('\t\t\tchange new_ins_list(0x%x) : %s %s, %s\n' % (change_head.ea, change_head.mnem, change_head.op1, change_head.op2))
        if not changed:
            isContinue = True
    else:
        isContinue = True
    if StrFind(cur.op1, '[esp'):
        is_op1_stack_pointer = True
        num = GetEspNumber(cur.op1) / 4
        if num > 0 or num == 0:
            push_count = num
        else:
            isContinue = False
    if isContinue:
        head2 = cur
        xor_pattern1_count = 1  # xor op1, op2 / xor op2, op1 / xor op1, op2 : xchg op1,op2
        xor_pattern1_op1_expect = cur.op2
        xor_pattern1_op2_expect = cur.op1
        xor_pattern1_available = True
        xor_pattern1_except_list = []
        if IsOpEqual(cur.op1, cur.op2):
            cur.mnem = 'mov'
            cur.op2 = '0'
            zero_flag = True
            isContinue = False

    if IsLowBitRegister(cur.op1):
        is_cur_op1_low_bit_reg = True
        top_reg = GetTopRegister(cur.op1)
    else:
        top_reg = cur.op1
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            isContinue = False
            break
        if head2.extend:
            print_log('\txor first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
        else:
            print_log('\txor first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
        if not IsHeadinExceptList(head2):
            if IsJump(head2.mnem):
                break
            compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
            if IsPushMnem(head2.mnem):
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        break
                else:
                    if IsOpEqual(head2.op1, cur.op1):
                        break
                    elif StrFind(head2.op1, cur.op1):
                        break
                    elif IsLowBitSameRegister(head2.op1, cur.op1):
                        break
                push_count += 1
            elif head2.mnem == 'pop':
                if is_op1_stack_pointer:
                    if head2.op1 == 'esp':
                        break
                    elif push_count == 0:
                        break
                if op1_reference_reg:
                    if IsOpEqual(head2.op1, cur.op1):
                        curHeadRemove()
                        break
                    elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                        break
                else:
                    if IsOpEqual(head2.op1, cur.op1):
                        curHeadRemove()
                        break
                    elif IsOpEqual(head2.op1, top_reg):
                        curHeadRemove()
                        break
                    elif IsLowBitSameRegister(head2.op1, top_reg):
                        break
                push_count -= 1
            elif head2.mnem == 'xor':
                normal_check = True
                if IsOpEqual(head2.op1, xor_pattern1_op1_expect) and IsOpEqual(head2.op2, xor_pattern1_op2_expect):
                    xor_pattern1_except_list.append(head2)
                    xor_pattern1_count += 1
                    if xor_pattern1_count == 3:
                        cur.mnem = 'xchg'
                        print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
                        isContinue = False
                        for head in xor_pattern1_except_list:
                            addHeadinExceptList(head)
                    else:
                        temp = xor_pattern1_op1_expect
                        xor_pattern1_op1_expect = xor_pattern1_op2_expect
                        xor_pattern1_op2_expect = temp
                    normal_check = False
                if normal_check:
                    if is_op1_stack_pointer:
                        if IsOpEqual(head2.op1, compare_str):
                            break
                        elif IsOpEqual(head2.op2, compare_str):
                            break
                        elif head2.op1 == 'esp':
                            break
                    else:
                        if IsOpEqual(head2.op2, top_reg):
                            break
                        if op1_reference_reg:
                            if IsOpEqual(head2.op1, cur.op1):
                                break
                            elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                                break
                        else:
                            if IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                                break
                            elif IsOpInReferenceRegIncludeSameReg(head2.op2, cur.op1):
                                break
                            elif IsLowBitSameRegister(head2.op2, top_reg):
                                break
                            if IsOpEqual(head2.op1, cur.op1):
                                break
                            elif IsLowBitSameRegister(head2.op1, top_reg):
                                break
                            elif IsOpEqual(head2.op1, top_reg):
                                break
            elif head2.mnem == 'mov':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        curHeadRemove()
                        break
                    elif IsOpEqual(head2.op2, compare_str):
                        break
                    elif head2.op1 == 'esp':
                        break
                else:
                    if IsOpEqual(head2.op2, top_reg):
                        break
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            curHeadRemove()
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            break
                    else:
                        if IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                            break
                        elif IsOpInReferenceRegIncludeSameReg(head2.op2, cur.op1):
                            break
                        elif IsLowBitSameRegister(head2.op2, top_reg):
                            break
                        if IsOpEqual(head2.op1, cur.op1):
                            curHeadRemove()
                            break
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            break
                        elif IsOpEqual(head2.op1, top_reg):
                            curHeadRemove()
                            break
            elif head2.mnem == 'movzx':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        curHeadRemove()
                        break
                    elif IsOpEqual(head2.op2, compare_str):
                        break
                    elif head2.op1 == 'esp':
                        break
                else:
                    if IsOpEqual(head2.op2, top_reg):
                        break
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            curHeadRemove()
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            break
                    else:
                        if IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                            break
                        elif IsOpInReferenceRegIncludeSameReg(head2.op2, cur.op1):
                            break
                        elif IsLowBitSameRegister(head2.op2, top_reg):
                            break
                        if IsOpEqual(head2.op1, cur.op1):
                            curHeadRemove()
                            break
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            break
                        elif IsOpEqual(head2.op1, top_reg):
                            curHeadRemove()
                            break
            elif IsCalcMnem(head2.mnem):
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str):
                        break
                    elif IsOpEqual(head2.op2, compare_str):
                        break
                    elif head2.op1 == 'esp':
                        break
                else:
                    if IsOpEqual(head2.op2, top_reg):
                        break
                    if op1_reference_reg:
                        if IsOpEqual(head2.op1, cur.op1):
                            break
                        elif not IsNumber(op1_reference_reg) and IsRegsInOpEqualTarget(head2.op1, cur.op1):
                            break
                    else:
                        if IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                            break
                        elif IsOpInReferenceRegIncludeSameReg(head2.op2, cur.op1):
                            break
                        elif IsLowBitSameRegister(head2.op2, top_reg):
                            break
                        if IsOpEqual(head2.op1, cur.op1):
                            break
                        elif IsLowBitSameRegister(head2.op1, top_reg):
                            break
                        elif IsOpEqual(head2.op1, top_reg):
                            break
            elif head2.mnem == 'xchg':
                if is_op1_stack_pointer:
                    if IsOpEqual(head2.op1, compare_str) or IsOpEqual(head2.op2, compare_str):
                        break
                else:
                    if IsOpEqual(head2.op1, cur.op1) or IsOpEqual(head2.op2, cur.op1):
                        break
                    elif StrFind(head2.op1, cur.op1) or StrFind(head2.op2, cur.op1):
                        break
def xchg_deob():
    global except_list, isInsert, cur
    global isContinue, head2
    isContinue = True
    head2 = cur
    late_modify_list = []
    encount_same_head = False
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            isContinue = False
            break
        if head2.extend:
            print_log('\txchg first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
        else:
            print_log('\txchg first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
        if not IsHeadinExceptList(head2):
            if IsJump(head2.mnem):
                break
            if IsPushMnem(head2.mnem):
                break
            elif head2.mnem == 'pop':
                break
            elif head2.mnem == 'add' and head2.op1 == 'esp':
                break
            elif head2.mnem == 'sub' and head2.op1 == 'esp':
                break
            elif head2.mnem == 'xchg':
                if (IsOpEqual(head2.op1, cur.op1) and IsOpEqual(head2.op2, cur.op2)) or \
                        (IsOpEqual(head2.op1, cur.op2) and IsOpEqual(head2.op2, cur.op1)):
                    curHeadRemove()
                    addHeadinExceptList(head2)
                    encount_same_head = True
                    break
            else:
                if head2.op1:
                    if IsOpEqual(head2.op1, cur.op1):
                        late_modify_list.append([head2.ea, head2.extend, 0, cur.op2])
                    elif IsOpEqual(head2.op1, cur.op2):
                        late_modify_list.append([head2.ea, head2.extend, 0, cur.op1])
                if head2.op2:
                    if IsOpEqual(head2.op2, cur.op1):
                        late_modify_list.append([head2.ea, head2.extend, 1, cur.op2])
                    elif IsOpEqual(head2.op2, cur.op2):
                        late_modify_list.append([head2.ea, head2.extend, 1, cur.op1])
    if encount_same_head:
        for info in late_modify_list:
            head = GetHead([info[0],info[1]])
            if info[2] == 0:
                addHeadinModifyList(head.ea, head.extend, head.mnem, info[3], head.op2)
            else:
                addHeadinModifyList(head.ea, head.extend, head.mnem, head.op1, info[3])
def pusha_deob():
    global except_list, isInsert, cur
    global isContinue, head2
    isContinue = True
    push_count = 0
    head2 = cur
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            break
        if head2.extend:
            print_log('\tpusha first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
        else:
            print_log('\tpusha first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
        if not IsHeadinExceptList(head2):
            if IsJump(head2.mnem):
                break
            if head2.mnem == 'pusha':
                push_count += 1
            if head2.mnem == 'popa':
                if push_count == 0:
                    addHeadinExceptList(head2)
                    curHeadRemove()
                    isContinue = False
                else:
                    push_count -= 1
def mov_deob():
    global isInsert, cur, isContinue, head2, zero_flag, restrict_jmp, over_jmp_mode
    global status_check_conditional_jmp, compare_str, original_reg_saved_offset_list, traceList
    global cant_change_because_not_number_offset_list, dont_care_not_num_offset_reference
    global test_record, deob_count
    if not over_jmp_mode:
        restrict_jmp = True
    if not status_check_conditional_jmp:
        status_check_conditional_jmp = True
    head2 = cur
    isContinue = True
    traceList = []
    push_count = 0
    is_op1_used = False
    is_op1_changed = False
    is_op1_reference = False # ex) [edx]
    is_op1_offset_reference = False
    is_not_number_offset_ref_used_insert_op = False
    is_not_number_offset_ref_used_op = False
    is_affect_range_offset_used_insert_op = False
    is_affect_range_offset_used_op = False
    op1_reference_reg = False # ex) cur.op1 = [edx] -> edx
    op1_offset_int = False
    is_op1_identify_real_value = False
    is_op1_stack_pointer = False # [esp] ~ [esp+%d]
    is_value_esp = False
    esp_stack_size = 0
    is_target_reg_stack_pointer = False
    is_target_reg_reference = False
    target_reg_reference_reg = False
    target_reg = cur.op2
    target_reg_real_value = False
    target_reg_real_value_insert_ea = False
    target_reg_insert_ea = False
    is_target_reg_insert_value = False
    is_target_reg_used = False
    is_target_reg_changed = False
    can_pattern1_change = False
    pattern1_except_list = []
    compare_str = False
    type_original_reg = False
    type_original_reg_checkpoint = 0
    pattern_type_original_reg_encounter_call = False
    original_reg_saved_offset_info = False
    pattern_type_original_reg_remove_list = []

    op1_top_reg = False
    target_reg_top_reg = False
    cur_reference_reg = GetReferenceReg(cur.op1)
    if cur_reference_reg and not StrFind(cur_reference_reg, 'esp'):
        if not IsNumber(cur_reference_reg):
            reference_offset = GetRegValue(cur_reference_reg)
            if not reference_offset == -1:
                if IsOpDword(cur.op1):
                    cur.op1 = 'dword ptr [%s]' % reference_offset
                if IsOpWord(cur.op1):
                    cur.op1 = 'word ptr [%s]' % reference_offset
                elif IsOpByte(cur.op1):
                    cur.op1 = 'byte ptr [%s]' % reference_offset
                if cur.extend:
                    print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                        cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                else:
                    print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                        cur.ea, cur.mnem, cur.op1, cur.op2))
    op1_reference_reg = GetReferenceReg(cur.op1)

    target_reg_reference_reg = GetReferenceReg(cur.op2)
    if target_reg_reference_reg and not StrFind(target_reg_reference_reg, 'esp'):
        if not IsNumber(target_reg_reference_reg):
            reference_offset = GetRegValue(target_reg_reference_reg)
            if not reference_offset == -1:
                cur.op2 = '[%s]' % reference_offset
                target_reg_reference_reg = reference_offset
                if cur.extend:
                    print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                        cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                else:
                    print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                        cur.ea, cur.mnem, cur.op1, cur.op2))
        if IsNumber(target_reg_reference_reg):
            if IsOpWord(cur.op1) or IsWordRegister(cur.op1):
                value = GetOffsetWordValueIfCan(target_reg_reference_reg)
                if not value == -1:
                    cur.op2 = int2hex(value)
                    target_reg_reference_reg = False
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                    else:
                        print_log(
                            '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
            elif IsOpByte(cur.op1) or IsLowHighRegister(cur.op1) or IsLowLowRegister(cur.op1):
                value = GetOffsetByteValueIfCan(target_reg_reference_reg)
                if not value == -1:
                    cur.op2 = int2hex(value)
                    target_reg_reference_reg = False
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                    else:
                        print_log(
                            '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
            else:
                value = GetOffsetDwordValueIfCan(target_reg_reference_reg)
                if not value == -1:
                    cur.op2 = int2hex(value)
                    target_reg_reference_reg = False
                    if cur.extend:
                        print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                            cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                    else:
                        print_log(
                            '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
    elif not target_reg_reference_reg and not IsNumber(cur.op2):
        value = GetRegValue(cur.op2)
        if not value == -1:
            if IsOpWord(cur.op2):
                value = hex2int(value)
                cur.op2 = int2hex(value & 0xFFFF)
            elif IsOpByte(cur.op2):
                value = hex2int(value)
                cur.op2 = int2hex(value & 0xFF)
            else:
                cur.op2 = value
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                    cur.ea, cur.mnem, cur.op1, cur.op2))
    target_reg_reference_reg = GetReferenceReg(cur.op2)

    if IsNumber(target_reg_reference_reg):
        value = GetOffsetDwordValueIfCan(target_reg_reference_reg)
        if not value == -1:
            cur.op2 = int2hex(value)
            target_reg_reference_reg = False
            print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
    if IsOpWord(cur.op1):
        high_word = GetOffsetDwordValueIfCan(cur.op1)
        if IsNumber(cur.op2) and not high_word == -1:
            high_word = GetHighWord(high_word)
            low_word = GetLowWord(hex2int(cur.op2))
            print_log('\t\thighword : 0x%x' % high_word)
            print_log('\t\tlowword : 0x%x' % low_word)
            cur.op1 = 'dword ptr [%s]' % op1_reference_reg
            cur.op2 = int2hex(high_word + low_word)
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                    cur.ea, cur.mnem, cur.op1, cur.op2))
        else:
            isContinue = False
    elif IsOpByte(cur.op1):
        high_word = GetOffsetDwordValueIfCan(cur.op1)
        if IsNumber(cur.op2) and not high_word == -1:
            high_word = high_word & 0xFFFFFF00
            low_word = hex2int(cur.op2) & 0xFF
            cur.op1 = 'dword ptr [%s]' % op1_reference_reg
            cur.op2 = int2hex(high_word + low_word)
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                    cur.ea, cur.mnem, cur.op1, cur.op2))
        else:
            isContinue = False
    if op1_reference_reg:
        is_op1_reference = True
        if IsNumber(op1_reference_reg):
            is_op1_offset_reference = True
            op1_offset_int = hex2int(op1_reference_reg)
            if not IsNumber(cur.op2) and not cur.op2 == 'esp':
                type_original_reg = True
    if target_reg_reference_reg:
        is_target_reg_reference = True
    if IsOpEqual(cur.op1, cur.op2):
        curHeadRemove()
        isContinue = False
    if StrFind(cur.op1, '[esp'):
        is_op1_stack_pointer = True
        num = GetEspNumber(cur.op1) / 4
        if num > 0 or num == 0:
            push_count = num
            print_log('\t\t\tpush_count : %d\n' % push_count)
        else:
            isContinue = False
    if StrFind(cur.op2, '[esp'):
        is_target_reg_stack_pointer = True
        num = GetEspNumber(cur.op2) / 4
        if num > 0 or num == 0:
            push_count = num
        else:
            isContinue = False
    if is_op1_stack_pointer and is_target_reg_stack_pointer:
        isContinue = False
    if IsNumber(cur.op2):
        is_op1_identify_real_value = True
    if IsLowBitRegister(cur.op1):
        op1_top_reg = GetTopRegister(cur.op1)
    if IsLowBitRegister(cur.op2):
        op2_top_reg = GetTopRegister(cur.op2)
    if cur.op2 == 'esp':
        is_value_esp = True
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            break
        if not IsHeadinExceptList(head2):
            if IsJump(head2.mnem):
                break
            if head2.extend:
                print_log('\tmov first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
            else:
                print_log('\tmov first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
            traceList.append([head2.ea, head2.extend])
            head2_op1_reference_reg = GetReferenceReg(head2.op1)
            head2_op2_reference_reg = GetReferenceReg(head2.op2)
            if is_op1_stack_pointer:
                compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                if IsOpEqual(head2.op2, compare_str):
                    if IsOpEqual(head2.op1, target_reg) and not is_op1_changed and not is_target_reg_changed:
                        addHeadinExceptList(head2)
                        continue
                    elif is_op1_identify_real_value:
                        if head2.mnem == 'mov' or head2.mnem == 'movzx' or IsCalcMnem(head2.mnem):
                            addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                            head2.op2 = cur.op2
                        else:
                            is_op1_used = True
                    else:
                        is_op1_used = True

            elif not head2_op2_reference_reg and op1_top_reg and not IsNumber(head2.op2) and IsPointSameRegister(head2.op2, cur.op1):
                is_op1_used = True
            elif head2_op2_reference_reg and op1_top_reg and not IsNumber(head2_op2_reference_reg) and IsPointSameRegInReferenceReg(head2.op2, cur.op1):
                is_op1_used = True
            elif IsLowBitSameRegister(head2.op2, cur.op1):
                if is_op1_identify_real_value:
                    if head2.mnem == 'mov' or head2.mnem == 'movzx' or IsCalcMnem(head2.mnem):
                        val = False
                        if IsWordRegister(head2.op2):
                            val = int2hex(hex2int(cur.op2) & 0xFFFF)
                            op1 = head2.op1
                            if not IsOpWord(head2.op1):
                                op1 = 'word ptr %s' % head2.op1
                            addHeadinModifyList(head2.ea, head2.extend, head2.mnem, op1, val)
                            head2.op1 = op1
                        elif IsLowHighRegister(head2.op2):
                            val = int2hex((hex2int(cur.op2) & 0xFF00) >> 8)
                            op1 = head2.op1
                            if not IsOpByte(head2.op1):
                                op1 = 'byte ptr %s' % head2.op1
                            addHeadinModifyList(head2.ea, head2.extend, head2.mnem, op1, val)
                            head2.op1 = op1
                        elif IsLowLowRegister(head2.op2):
                            val = int2hex(hex2int(cur.op2) & 0xFF)
                            op1 = head2.op1
                            if not IsOpByte(head2.op1):
                                op1 = 'byte ptr %s' % head2.op1
                            addHeadinModifyList(head2.ea, head2.extend, head2.mnem, op1, val)
                            head2.op1 = op1
                        head2.op2 = val
                    else:
                        is_op1_used = True
                else:
                    is_op1_used = True
            elif IsOpEqualReferenceReg(head2.op2, cur.op1):
                if is_op1_identify_real_value:
                    if IsOpWord(head2.op2):
                        changed_op = 'word ptr [%s]' % cur.op2
                    elif IsOpByte(head2.op2):
                        changed_op = 'byte ptr [%s]' % cur.op2
                    else:
                        changed_op = '[%s]' % cur.op2
                    addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, changed_op)
                    head2.op2 = changed_op
                else:
                    is_op1_used = True
            elif IsOpEqual(head2.op2, target_reg):
                is_target_reg_used = True
            elif IsLowBitSameRegister(head2.op2, target_reg):
                is_target_reg_used = True
            elif IsOpEqualReferenceReg(head2.op2, target_reg):
                is_target_reg_used = True
            if IsPushMnem(head2.mnem):
                if IsOpEqual(cur.op1, 'esp'):
                    break
                if is_target_reg_stack_pointer or is_op1_stack_pointer:
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                if is_op1_stack_pointer and IsOpEqual(head2.op1, compare_str):
                    if is_op1_identify_real_value:
                        addHeadinModifyList(head2.ea, head2.extend, head2.mnem, cur.op2, False)
                        head2.op2 = cur.op2
                    else:
                        is_op1_used = True
                elif is_target_reg_stack_pointer and IsOpEqual(head2.op1, compare_str):
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if IsOpEqual(head2.op2, compare_str):
                        is_target_reg_used = True
                elif not is_op1_stack_pointer and IsOpEqual(head2.op1, cur.op1):
                    if is_op1_offset_reference:
                        if pattern_type_original_reg_encounter_call and not is_not_number_offset_ref_used_insert_op and type_original_reg_checkpoint == 0:
                            pattern_type_original_reg_remove_list.append(head2)
                            type_original_reg_checkpoint = 1
                        elif not is_affect_range_offset_used_insert_op and not is_not_number_offset_ref_used_insert_op and not is_target_reg_changed:
                            if not is_op1_changed:
                                addHeadinModifyList(head2.ea, head2.extend, head2.mnem, cur.op2, False)
                                head2.op1 = cur.op2
                            else:
                                is_op1_used = True
                        else:
                            is_op1_used = True
                    elif is_op1_identify_real_value:
                        addHeadinModifyList(head2.ea, head2.extend, head2.mnem, cur.op2, False)
                        head2.op2 = cur.op2
                    else:
                        is_op1_used = True
                elif pattern_type_original_reg_encounter_call and GetSavedOriginalRegOffsetInfo(head2_op1_reference_reg):
                    saved_org_reg_offset_info = GetSavedOriginalRegOffsetInfo(head2_op1_reference_reg)
                    if saved_org_reg_offset_info:
                        if type_original_reg_checkpoint == 0:
                            pattern_type_original_reg_remove_list.append(head2)
                            type_original_reg_checkpoint = 2
                            continue
                elif not head2_op1_reference_reg and op1_top_reg and not IsNumber(head2.op1) and IsPointSameRegister(head2.op1, cur.op1):
                    is_op1_used = True
                elif not is_op1_stack_pointer and StrFind(head2.op1, cur.op1):
                    is_op1_used = True
                elif not is_target_reg_stack_pointer and IsOpEqual(head2.op1, target_reg):
                    is_target_reg_used = True
                elif not is_target_reg_stack_pointer and StrFind(head2.op1, target_reg):
                    is_target_reg_used = True
                if is_op1_offset_reference:
                    if head2_op1_reference_reg and IsNumber(head2_op1_reference_reg):
                        head2_op1_offset_int = hex2int(head2_op1_reference_reg)
                        if (op1_offset_int <= head2_op1_offset_int + 3) and (op1_offset_int >= head2_op1_offset_int - 3):
                            is_affect_range_offset_used_op = True
                if head2_op1_reference_reg and not IsNumber(head2_op1_reference_reg):
                    if not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
                push_count += 1
            elif head2.mnem == 'pop':
                if pattern_type_original_reg_encounter_call and type_original_reg_checkpoint > 2:
                    if type_original_reg_checkpoint == 3:
                        if hex2int(head2_op1_reference_reg) == original_reg_saved_offset_info[1]:
                            pattern_type_original_reg_remove_list.append(head2)
                            t_reg = cur.op2
                            t_index = original_reg_saved_offset_info[0]
                            cur.op2 = original_reg_saved_offset_info[2]
                            new_ins_list[t_index].op2 = t_reg
                            original_reg_saved_offset_info[2] = t_reg
                            test_record.append([deob_count, cur.ea])
                            if cur.extend:
                                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                            else:
                                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                                    cur.ea, cur.mnem, cur.op1, cur.op2))
                            print_log('\t\tnew_ins_list(0x%x) change : %s %s, %s\n' % (
                                new_ins_list[t_index].ea, new_ins_list[t_index].mnem, new_ins_list[t_index].op1, new_ins_list[t_index].op2))
                            for head in pattern_type_original_reg_remove_list:
                                addHeadinExceptList(head)
                            break
                    elif type_original_reg_checkpoint == 4:
                        if hex2int(head2_op1_reference_reg) == op1_offset_int:
                            pattern_type_original_reg_remove_list.append(head2)
                            t_reg = cur.op2
                            t_index = original_reg_saved_offset_info[0]
                            cur.op2 = original_reg_saved_offset_info[2]
                            new_ins_list[t_index].op2 = t_reg
                            original_reg_saved_offset_info[2] = t_reg
                            test_record.append([deob_count, cur.ea])
                            if cur.extend:
                                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                            else:
                                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                                    cur.ea, cur.mnem, cur.op1, cur.op2))
                            print_log('\t\tnew_ins_list(0x%x) change : %s %s, %s\n' % (
                                new_ins_list[t_index].ea, new_ins_list[t_index].mnem, new_ins_list[t_index].op1, new_ins_list[t_index].op2))
                            for head in pattern_type_original_reg_remove_list:
                                addHeadinExceptList(head)
                            break
                    break
                push_count -= 1
                print_log('\t\t\tpush_count check : %d\n' % push_count)
                if IsOpEqual(cur.op1, 'esp'):
                    break
                elif is_op1_stack_pointer or is_target_reg_stack_pointer:
                    if IsOpEqual(head2.op1, 'esp'):
                        break
                if is_op1_stack_pointer:
                    if push_count < 0:
                        break
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if IsOpEqual(head2.op1, compare_str):
                        break
                elif IsOpEqual(head2.op1, cur.op1):
                    if not is_op1_used and not is_affect_range_offset_used_op:
                        curHeadRemove()
                    break
                elif StrFind(head2.op1, cur.op1):
                    is_op1_used = True
                elif IsOpEqual(head2.op1, op1_reference_reg):
                    break
                if is_target_reg_stack_pointer:
                    if push_count < 0:
                        break
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if IsOpEqual(head2.op1, compare_str):
                        is_target_reg_identify_real_value = False
                        is_target_reg_changed = True
                        if is_target_reg_insert_value:
                            can_pattern1_change = False
                elif IsOpEqual(head2.op1, target_reg):
                    is_target_reg_identify_real_value = False
                    is_target_reg_changed = True
                    if is_target_reg_insert_value:
                        can_pattern1_change = False
                elif StrFind(head2.op1, target_reg):
                    is_target_reg_used = True
                elif IsOpEqual(head2.op1, target_reg_reference_reg):
                    break
                if head2_op1_reference_reg and not IsNumber(head2_op1_reference_reg):
                    if not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
            elif head2.mnem == 'mov':
                if pattern_type_original_reg_encounter_call and type_original_reg_checkpoint > 0 and not is_target_reg_changed:
                    if type_original_reg_checkpoint == 1:
                        print_log('\t\ttype_original_reg_checkpoint1\n')
                        if IsOpEqual(head2.op1, cur.op1):
                            if head2_op2_reference_reg and IsNumber(head2_op2_reference_reg):
                                if not original_reg_saved_offset_info:
                                    original_reg_saved_offset_info = GetSavedOriginalRegOffsetInfo(head2_op2_reference_reg)
                                    if original_reg_saved_offset_info:
                                        pattern_type_original_reg_remove_list.append(head2)
                                        type_original_reg_checkpoint = 3
                                        continue
                        break
                    elif type_original_reg_checkpoint == 2:
                        print_log('\t\ttype_original_reg_checkpoint2\n')
                        if IsOpEqual(head2.op2, cur.op1):
                            if head2_op1_reference_reg and IsNumber(head2_op1_reference_reg):
                                if not original_reg_saved_offset_info:
                                    original_reg_saved_offset_info = GetSavedOriginalRegOffsetInfo(head2_op1_reference_reg)
                                    for info in original_reg_saved_offset_list:
                                        print_log('\t\t0x%x : %s\n' % (info[1], info[2]))
                                    if original_reg_saved_offset_info:
                                        print_log('\t\ttype_original_reg_checkpoint = 4\n')
                                        pattern_type_original_reg_remove_list.append(head2)
                                        type_original_reg_checkpoint = 4
                                        continue
                        break
                elif pattern_type_original_reg_encounter_call and type_original_reg_checkpoint == 0 and not is_op1_used and \
                        head2_op1_reference_reg and IsNumber(head2_op1_reference_reg):
                    if IsOpEqual(head2.op2, cur.op1):
                        original_reg_saved_offset_info = GetSavedOriginalRegOffsetInfo(head2_op1_reference_reg)
                        if not original_reg_saved_offset_info:
                            prev_head = PrevHead(head2)
                            if not (prev_head.mnem == 'push' and IsOpEqual(head2.op1, prev_head.op1)):
                                addHeadInNewInsList(head2.mnem, head2.op1, cur.op2)
                                addHeadinExceptList(head2)
                                traceTemp = list(traceList)
                                traceTemp.pop()
                                while len(traceTemp) > 1:
                                    head = GetHead(traceTemp.pop())
                                    print_log('\t\t%d' % len(traceTemp))
                                    if head.extend:
                                        print_log(
                                            '\t\ttrace  (0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                                    else:
                                        print_log('\t\ttrace  (0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                                    if head.mnem == 'mov':
                                        if IsOpEqual(head.op1, head2.op1):
                                            addHeadinExceptList(head)
                                    elif head.mnem == 'movzx':
                                        if IsOpEqual(head.op1, head2.op1):
                                            addHeadinExceptList(head)
                                    elif IsCalcMnem(head.mnem):
                                        if IsOpEqual(head.op1, head2.op1):
                                            addHeadinExceptList(head)
                                break
                if not is_op1_stack_pointer and IsOpEqual(head2.op2, cur.op1):
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if is_target_reg_stack_pointer and IsOpEqual(head2.op1, compare_str) and not is_op1_changed and not is_target_reg_changed:
                        addHeadinExceptList(head2)
                        continue
                    elif not is_target_reg_stack_pointer and IsOpEqual(head2.op1, target_reg) and not is_op1_changed and not is_target_reg_changed:
                        addHeadinExceptList(head2)
                        continue
                    elif is_op1_offset_reference:
                        if not is_affect_range_offset_used_insert_op and not is_target_reg_changed:
                            if not is_op1_changed:
                                if dont_care_not_num_offset_reference or not is_not_number_offset_ref_used_insert_op:
                                    addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                                    head2.op2 = cur.op2
                            else:
                                is_op1_used = True
                        else:
                            is_op1_used = True
                    elif is_op1_identify_real_value:
                        if IsWordRegister(head2.op2):
                            if not IsOpWord(head2.op1):
                                head2.op1 = 'word ptr %s' % head2.op1
                        elif IsLowHighRegister(head2.op2) or IsLowLowRegister(head2.op2):
                            if not IsOpByte(head2.op1):
                                head2.op1 = 'byte ptr %s' % head2.op1
                        addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                        head2.op2 = cur.op2
                    else:
                        is_op1_used = True
                if is_target_reg_stack_pointer or is_op1_stack_pointer:
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if IsOpEqual(head2.op1, 'esp'):
                        break
                if is_op1_stack_pointer and IsOpEqual(head2.op1, compare_str):
                    if not is_op1_used and not is_affect_range_offset_used_op:
                        curHeadRemove()
                    break
                elif not is_op1_stack_pointer and IsOpEqual(head2.op1, cur.op1):
                    if not is_op1_used and not is_affect_range_offset_used_op:
                        curHeadRemove()
                    break
                elif not is_op1_stack_pointer and not head2_op1_reference_reg and op1_top_reg and IsPointSameRegister(head2.op1, cur.op1):
                    if head2.op1 == op1_top_reg:
                        if not is_op1_used:
                            curHeadRemove()
                            break
                    is_op1_identify_real_value = False
                    is_op1_changed = True
                elif not is_op1_stack_pointer and IsLowBitSameRegister(head2.op1, cur.op1):
                    if not is_op1_used and not is_affect_range_offset_used_op:
                        if is_op1_identify_real_value and IsNumber(head2.op2):
                            if IsWordRegister(head2.op1):
                                high_word = GetHighWord(cur.op2)
                                low_word = GetLowWord(head2.op2)
                                curHeadRemove()
                                addHeadinModifyList(head2.ea, head2.extend, head2.mnem, cur.op1,
                                                    int2hex(high_word + low_word))
                            elif IsLowHighRegister(head2.op1):
                                high_word = GetHighWord(cur.op2)
                                low_high_word = hex2int(head2.op2) & 0xFF00
                                low_low_word = hex2int(cur.op2) & 0xFF
                                curHeadRemove()
                                addHeadinModifyList(head2.ea, head2.extend, head2.mnem, cur.op1,
                                                    int2hex(high_word + low_high_word + low_low_word))
                            elif IsLowLowRegister(head2.op1):
                                high_word = GetHighWord(cur.op2)
                                low_high_word = hex2int(cur.op2) & 0xFF00
                                low_low_word = hex2int(head2.op2) & 0xFF
                                curHeadRemove()
                                addHeadinModifyList(head2.ea, head2.extend, head2.mnem, cur.op1,
                                                    int2hex(high_word + low_high_word + low_low_word))
                    break
                elif not is_op1_stack_pointer and IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1): #mov eax, ecx / mov [eax], op2
                    if is_value_esp:
                        change_value = 'dword ptr [esp+%s]' % int2hex(esp_stack_size)
                        addHeadinModifyList(head2.ea, head2.extend, head2.mnem, change_value, head2.op2)
                    else:
                        is_op1_used = True
                elif IsOpEqual(head2.op1, op1_reference_reg): # mov [edx], ecx / mov edx, 302
                    break
                elif is_target_reg_stack_pointer and IsOpEqual(head2.op1, compare_str):
                    if IsNumber(head2.op2) and not is_target_reg_insert_value:
                        target_reg_real_value_insert_ea = [head2.ea, head2.extend]
                        target_reg_real_value = head2.op2
                        is_target_reg_insert_value = True
                        is_target_reg_identify_real_value = True
                        is_target_reg_changed = True
                        can_pattern1_change = True
                        pattern1_except_list.append([head2.ea, head2.extend])
                    elif IsNumber(head2.op2) and is_target_reg_insert_value:
                        is_target_reg_changed = True
                        can_pattern1_change = False
                    else:
                        is_target_reg_changed = True
                        is_target_reg_insert_value = True
                        is_target_reg_identify_real_value = False
                elif not is_target_reg_stack_pointer and IsOpEqual(head2.op1, target_reg):
                    if IsNumber(head2.op2) and not is_target_reg_insert_value:
                        target_reg_real_value_insert_ea = [head2.ea, head2.extend]
                        target_reg_insert_ea = [head2.ea, head2.extend]
                        target_reg_real_value = head2.op2
                        is_target_reg_insert_value = True
                        is_target_reg_identify_real_value = True
                        is_target_reg_changed = True
                        can_pattern1_change = True
                        is_target_reg_used = False
                        pattern1_except_list.append([head2.ea, head2.extend])
                    elif not IsNumber(head2.op2) and not is_target_reg_insert_value:
                        target_reg_real_value_insert_ea = False
                        target_reg_insert_ea = [head2.ea, head2.extend]
                        target_reg_real_value = False
                        is_target_reg_insert_value = True
                        is_target_reg_identify_real_value = False
                        is_target_reg_changed = True
                        can_pattern1_change = False
                        is_target_reg_used = False
                    elif IsNumber(head2.op2) and is_target_reg_insert_value:
                        if not is_target_reg_used:
                            if IsNumber(head2.op2):
                                if pattern1_except_list:
                                    delInfoInList(pattern1_except_list, target_reg_insert_ea[0], target_reg_insert_ea[1])
                                addHeadinExceptList(target_reg_insert_ea[0], target_reg_insert_ea[1])
                                target_reg_real_value_insert_ea = [head2.ea, head2.extend]
                                target_reg_insert_ea = [head2.ea, head2.extend]
                                target_reg_real_value = head2.op2
                                is_target_reg_insert_value = True
                                is_target_reg_identify_real_value = True
                                is_target_reg_changed = True
                                can_pattern1_change = True
                                pattern1_except_list.append([head2.ea, head2.extend])
                            else:
                                is_target_reg_changed = True
                                is_target_reg_insert_value = True
                                is_target_reg_identify_real_value = False
                        else:
                            is_target_reg_changed = True
                            can_pattern1_change = False
                            is_target_reg_identify_real_value = False
                    else:
                        is_target_reg_changed = True
                        is_target_reg_insert_value = True
                        is_target_reg_identify_real_value = False
                elif not is_target_reg_stack_pointer and IsLowBitSameRegister(head2.op1, target_reg):
                    break
                elif not is_target_reg_stack_pointer and IsOpInReferenceRegIncludeSameReg(head2.op1, target_reg):
                    is_target_reg_used = True
                elif IsOpEqual(head2.op1, target_reg_reference_reg): # mov edx, [ecx] / mov ecx, 302
                    break
                if is_op1_offset_reference:
                    if head2_op1_reference_reg and IsNumber(head2_op1_reference_reg):
                        head2_op1_offset_int = hex2int(head2_op1_reference_reg)
                        if (op1_offset_int <= head2_op1_offset_int + 3) and (op1_offset_int >= head2_op1_offset_int - 3):
                            is_affect_range_offset_used_insert_op = True
                    elif head2_op2_reference_reg and IsNumber(head2_op2_reference_reg):
                        head2_op2_offset_int = hex2int(head2_op2_reference_reg)
                        if (op1_offset_int <= head2_op2_offset_int + 3) and (op1_offset_int >= head2_op2_offset_int - 3):
                            is_affect_range_offset_used_op = True
                if head2_op1_reference_reg:
                    if not IsNumber(head2_op1_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
                if head2_op2_reference_reg:
                    if not IsNumber(head2_op2_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
            elif head2.mnem == 'movzx':
                if not is_op1_stack_pointer and IsOpEqual(head2.op2, cur.op1):
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if is_target_reg_stack_pointer and IsOpEqual(head2.op1,
                                                                 compare_str) and not is_op1_changed and not is_target_reg_changed:
                        addHeadinExceptList(head2)
                        continue
                    elif not is_target_reg_stack_pointer and IsOpEqual(head2.op1,
                                                                       target_reg) and not is_op1_changed and not is_target_reg_changed:
                        addHeadinExceptList(head2)
                        continue
                    elif is_op1_offset_reference:
                        if not is_affect_range_offset_used_insert_op and not is_not_number_offset_ref_used_insert_op and not is_target_reg_changed:
                            if not is_op1_changed:
                                addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                                head2.op2 = cur.op2
                            else:
                                is_op1_used = True
                        else:
                            is_op1_used = True
                    elif is_op1_identify_real_value:
                        if IsWordRegister(head2.op2):
                            if not IsOpWord(head2.op1):
                                head2.op1 = 'word ptr %s' % head2.op1
                        elif IsLowHighRegister(head2.op2) or IsLowLowRegister(head2.op2):
                            if not IsOpByte(head2.op1):
                                head2.op1 = 'byte ptr %s' % head2.op1
                        addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                        head2.op2 = cur.op2
                    else:
                        is_op1_used = True
                if is_target_reg_stack_pointer or is_op1_stack_pointer:
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if IsOpEqual(head2.op1, 'esp'):
                        break
                if is_op1_stack_pointer and IsOpEqual(head2.op1, compare_str):
                    if not is_op1_used and not is_affect_range_offset_used_op:
                        curHeadRemove()
                    break
                elif not is_op1_stack_pointer and IsOpEqual(head2.op1, cur.op1):
                    if not is_op1_used and not is_affect_range_offset_used_op:
                        curHeadRemove()
                    break
                elif not is_op1_stack_pointer and not head2_op1_reference_reg and op1_top_reg and IsPointSameRegister(head2.op1, cur.op1):
                    if head2.op1 == op1_top_reg:
                        if not is_op1_used:
                            curHeadRemove()
                            break
                    is_op1_identify_real_value = False
                    is_op1_changed = True
                elif not is_op1_stack_pointer and StrFind(head2.op1, cur.op1): #mov eax, ecx / movzx [eax+ebx], word ptr op2
                    is_op1_used = True
                elif IsOpEqual(head2.op1, op1_reference_reg): # mov [edx], ecx / mov edx, 302
                    break
                elif is_target_reg_stack_pointer and IsOpEqual(head2.op1, compare_str):
                    target_reg_real_value_insert_ea = False
                    target_reg_insert_ea = [head2.ea, head2.extend]
                    target_reg_real_value = False
                    is_target_reg_changed = True
                    is_target_reg_insert_value = True
                    is_target_reg_identify_real_value = False
                    can_pattern1_change = False
                    is_target_reg_used = False
                elif not is_target_reg_stack_pointer and IsOpEqual(head2.op1, target_reg):
                    target_reg_real_value_insert_ea = False
                    target_reg_insert_ea = [head2.ea, head2.extend]
                    target_reg_real_value = False
                    is_target_reg_changed = True
                    is_target_reg_insert_value = True
                    is_target_reg_identify_real_value = False
                    can_pattern1_change = False
                    is_target_reg_used = False
                elif not is_target_reg_stack_pointer and StrFind(head2.op1, target_reg):
                    is_target_reg_used = True
                elif IsOpEqual(head2.op1, target_reg_reference_reg): # mov edx, [ecx] / movzx ecx, 302
                    break
                if is_op1_offset_reference:
                    if head2_op1_reference_reg and IsNumber(head2_op1_reference_reg):
                        head2_op1_offset_int = hex2int(head2_op1_reference_reg)
                        if (op1_offset_int >= head2_op1_offset_int + 3) and (op1_offset_int <= head2_op1_offset_int - 3):
                            is_affect_range_offset_used_insert_op = True
                    elif head2_op2_reference_reg and IsNumber(head2_op2_reference_reg):
                        head2_op2_offset_int = hex2int(head2_op2_reference_reg)
                        if (op1_offset_int <= head2_op2_offset_int + 3) and (op1_offset_int >= head2_op2_offset_int - 3):
                            is_affect_range_offset_used_op = True
                if head2_op1_reference_reg:
                    if not IsNumber(head2_op1_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
                if head2_op2_reference_reg:
                    if not IsNumber(head2_op2_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
            elif IsCalcMnem(head2.mnem):
                if not is_op1_stack_pointer and IsOpEqual(head2.op2, cur.op1):
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if is_op1_offset_reference:
                        if not is_affect_range_offset_used_insert_op and not is_target_reg_changed:
                            if not is_op1_changed:
                                if dont_care_not_num_offset_reference or not is_not_number_offset_ref_used_insert_op:
                                    addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                                    head2.op2 = cur.op2
                            else:
                                is_op1_used = True
                        else:
                            is_op1_used = True
                    elif is_op1_identify_real_value:
                        if IsWordRegister(head2.op2):
                            if not IsOpWord(head2.op1):
                                head2.op1 = 'word ptr %s' % head2.op1
                        elif IsLowHighRegister(head2.op2) or IsLowLowRegister(head2.op2):
                            if not IsOpByte(head2.op1):
                                head2.op1 = 'byte ptr %s' % head2.op1
                        addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                        head2.op2 = cur.op2
                    else:
                        is_op1_used = True
                if head2.mnem == 'add' and head2.op1 == 'esp':
                    if not IsNumber(head2.op2):
                        break
                    else:
                        push_count -= hex2int(head2.op2) / 4
                        if is_op1_stack_pointer or is_target_reg_stack_pointer:
                            if push_count < 0:
                                break
                        continue
                elif head2.mnem == 'sub' and head2.op1 == 'esp':
                    if not IsNumber(head2.op2):
                        break
                    else:
                        push_count += hex2int(head2.op2) / 4
                        continue
                if is_target_reg_stack_pointer or is_op1_stack_pointer:
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                if is_target_reg_stack_pointer and IsOpEqual(head2.op1, compare_str):
                    if is_target_reg_insert_value and is_target_reg_identify_real_value:
                        if IsNumber(head2.op2):
                            if not is_target_reg_used:
                                target_reg_real_value = int2hex(calc(head2.mnem, target_reg_real_value, head2.op2))
                                ea = target_reg_real_value_insert_ea[0]
                                extend = target_reg_real_value_insert_ea[1]
                                addHeadinModifyList(ea, extend, 'mov', target_reg, target_reg_real_value)
                                addHeadinExceptList(head2)
                                head2_op1_reference_reg = False
                                head2_op2_reference_reg = False
                            else:
                                is_target_reg_identify_real_value = False
                                can_pattern1_change = False
                        else:
                            is_target_reg_identify_real_value = False
                            can_pattern1_change = False
                        is_target_reg_changed = True
                    else:
                        is_target_reg_changed = True
                elif is_op1_stack_pointer and IsOpEqual(head2.op1, compare_str):
                    if IsOpEqual(head2.op1, head2.op2):
                        if head2.mnem == 'or':
                            addHeadinExceptList(head2)
                            head2_op1_reference_reg = False
                            head2_op2_reference_reg = False
                        else:
                            is_op1_identify_real_value = False
                            is_op1_changed = True
                    elif is_op1_identify_real_value:
                        if IsNumber(cur.op2) and IsNumber(head2.op2):
                            cur.op2 = int2hex(calc(head2.mnem, cur.op2, head2.op2))
                            print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
                            addHeadinExceptList(head2)
                            head2_op1_reference_reg = False
                            head2_op2_reference_reg = False
                        elif not IsNumber(head2.op2):
                            is_op1_identify_real_value = False
                        is_op1_changed = True
                    else:
                        break
                elif not is_target_reg_stack_pointer and IsOpEqual(head2.op1, target_reg):
                    if is_target_reg_insert_value and is_target_reg_identify_real_value:
                        if IsNumber(head2.op2) or head2.op2 is False:
                            if not is_target_reg_used:
                                target_reg_real_value = int2hex(calc(head2.mnem, target_reg_real_value, head2.op2))
                                ea = target_reg_real_value_insert_ea[0]
                                extend = target_reg_real_value_insert_ea[1]
                                addHeadinModifyList(ea, extend, 'mov', target_reg, target_reg_real_value)
                                addHeadinExceptList(head2)
                                head2_op1_reference_reg = False
                                head2_op2_reference_reg = False
                            else:
                                is_target_reg_identify_real_value = False
                                can_pattern1_change = False
                        else:
                            is_target_reg_identify_real_value = False
                            can_pattern1_change = False
                        is_target_reg_changed = True
                    else:
                        is_target_reg_changed = True
                elif not is_target_reg_stack_pointer and not IsNumber(GetReferenceReg(head2.op1)) and StrFind(head2.op1, target_reg):
                    is_target_reg_used = True
                elif is_target_reg_reference and IsOpEqual(head2.op1, target_reg_reference_reg):
                    if is_target_reg_stack_pointer:
                        if not IsNumber(head2.op2):
                            break
                        else:
                            if head2.mnem == 'add':
                                push_count -= (hex2int(head2.op2) / 4)
                                if push_count < 0:
                                    break
                            elif head2.mnem == 'sub':
                                push_count += (hex2int(head2.op2) / 4)
                            else:
                                break
                    else:
                        break
                elif not is_op1_stack_pointer and not is_op1_offset_reference and IsOpEqual(head2.op1, cur.op1):
                    n_head = NextHead(head2)
                    if n_head:
                        if n_head.mnem == 'jz' or n_head.mnem == 'jnz' or n_head.mnem == 'jbe':
                            break
                    if IsOpEqual(head2.op1, head2.op2):
                        if head2.mnem == 'or':
                            addHeadinExceptList(head2)
                            head2_op1_reference_reg = False
                            head2_op2_reference_reg = False
                        else:
                            is_op1_identify_real_value = False
                            is_op1_changed = True
                    elif is_op1_identify_real_value and not is_op1_used:
                        if IsNumber(cur.op2) and (IsNumber(head2.op2) or head2.op2 is False):
                            cur.op2 = int2hex(calc(head2.mnem, cur.op2, head2.op2))
                            print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
                            addHeadinExceptList(head2)
                            head2_op1_reference_reg = False
                            head2_op2_reference_reg = False
                        elif not IsNumber(head2.op2):
                            is_op1_identify_real_value = False
                            if head2.op2 == 'esp':
                                is_value_esp = True
                                esp_stack_size = hex2int(cur.op2)
                        is_op1_changed = True
                    elif not is_op1_identify_real_value and is_value_esp:
                        if IsNumber(head2.op2):
                            if head2.mnem == 'add':
                                esp_stack_size += hex2int(head2.op2)
                            elif head2.mnem == 'sub':
                                esp_stack_size -= hex2int(head2.op2)
                            else:
                                break
                        else:
                            break
                    else:
                        break
                elif not is_op1_stack_pointer and not head2_op1_reference_reg and op1_top_reg and IsPointSameRegister(head2.op1, cur.op1):
                    is_op1_identify_real_value = False
                    is_op1_changed = True
                elif not is_op1_stack_pointer and not is_op1_offset_reference and IsOpInReferenceRegIncludeSameReg(head2.op1, cur.op1):
                    is_op1_used = True
                elif not is_op1_stack_pointer and not is_op1_offset_reference and IsLowBitSameRegister(head2.op1, cur.op1):
                    if is_op1_identify_real_value and not is_op1_used:
                        if IsNumber(cur.op2) and (IsNumber(head2.op2) or head2.op2 is False):
                            if IsWordRegister(head2.op1):
                                t_val1 = hex2int(cur.op2) & 0xFFFF0000
                                t_val2 = calc(head2.mnem, hex2int(cur.op2) & 0xFFFF, head2.op2) & 0xFFFF
                                cur.op2 = int2hex(t_val1 + t_val2)
                            elif IsLowHighRegister(head2.op1):
                                t_val1 = hex2int(cur.op2) & 0xFFFF00FF
                                t_val2 = calc(head2.mnem, (hex2int(cur.op2) & 0xFF00) >> 8, head2.op2) & 0xFF
                                cur.op2 = int2hex(t_val1 + t_val2)
                            elif IsLowLowRegister(head2.op1):
                                t_val1 = hex2int(cur.op2) & 0xFFFFFF00
                                t_val2 = calc(head2.mnem, hex2int(cur.op2) & 0xFF, head2.op2) & 0xFF
                                cur.op2 = int2hex(t_val1 + t_val2)
                            print_log('\t\tcurrent target change : %s %s, %s\n' % (cur.mnem, cur.op1, cur.op2))
                            addHeadinExceptList(head2)
                            head2_op1_reference_reg = False
                            head2_op2_reference_reg = False
                        elif not IsNumber(head2.op2):
                            is_op1_identify_real_value = False
                        is_op1_changed = True
                    else:
                        break
                elif not is_op1_stack_pointer and not is_op1_offset_reference and IsLowBitSameRegister(head2.op2, cur.op1):
                    is_op1_used = True
                elif is_op1_offset_reference:
                    if IsOpEqual(head2.op1, cur.op1):
                        if is_op1_identify_real_value:
                            if IsNumber(head2.op2) or head2.op2 is False:
                                if IsOpDword(cur.op1) and IsOpDword(head2.op1):
                                    addHeadinModifyList(head2.ea, head2.extend, 'mov', cur.op1,
                                                        int2hex(calc(head2.mnem, cur.op2, head2.op2)))
                                    if not is_not_number_offset_ref_used_insert_op and not is_not_number_offset_ref_used_op:
                                        if not is_op1_used:
                                            curHeadRemove()
                                elif IsOpWord(cur.op1) and IsOpWord(head2.op1):
                                    addHeadinModifyList(head2.ea, head2.extend, 'mov', cur.op1,
                                                        int2hex(calc(head2.mnem, cur.op2, head2.op2)))
                                    if not is_not_number_offset_ref_used_insert_op and not is_not_number_offset_ref_used_op:
                                        if not is_op1_used:
                                            curHeadRemove()
                                elif IsOpByte(cur.op1) and IsOpByte(head2.op1):
                                    addHeadinModifyList(head2.ea, head2.extend, 'mov', cur.op1,
                                                        int2hex(calc(head2.mnem, cur.op2, head2.op2)))
                                    if not is_not_number_offset_ref_used_insert_op and not is_not_number_offset_ref_used_op:
                                        if not is_op1_used:
                                            curHeadRemove()
                                break
                            else:
                                break
                        else:
                            break
                elif is_op1_reference and IsOpEqual(head2.op1, op1_reference_reg):
                    if is_op1_stack_pointer:
                        if not IsNumber(head2.op2):
                            break
                        else:
                            if head2.mnem == 'add':
                                push_count -= (hex2int(head2.op2) / 4)
                                if push_count < 0:
                                    break
                            elif head2.mnem == 'sub':
                                push_count += (hex2int(head2.op2) / 4)
                            else:
                                break
                    else:
                        break
                if is_op1_offset_reference:
                    if head2_op1_reference_reg and IsNumber(head2_op1_reference_reg):
                        head2_op1_offset_int = hex2int(head2_op1_reference_reg)
                        if (op1_offset_int >= head2_op1_offset_int + 3) and (op1_offset_int <= head2_op1_offset_int - 3):
                            is_affect_range_offset_used_insert_op = True
                    elif head2_op2_reference_reg and IsNumber(head2_op2_reference_reg):
                        head2_op2_offset_int = hex2int(head2_op2_reference_reg)
                        if (op1_offset_int <= head2_op2_offset_int + 3) and (op1_offset_int >= head2_op2_offset_int - 3):
                            is_affect_range_offset_used_op = True
                if head2_op1_reference_reg:
                    if not IsNumber(head2_op1_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
                if head2_op2_reference_reg:
                    if not IsNumber(head2_op2_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
            elif head2.mnem == 'xchg':
                if not is_op1_stack_pointer and IsOpEqual(head2.op2, cur.op1):
                    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                    if is_target_reg_stack_pointer and IsOpEqual(head2.op1,
                                                                 compare_str) and not is_op1_changed and not is_target_reg_changed:
                        addHeadinExceptList(head2)
                        continue
                    elif not is_target_reg_stack_pointer and IsOpEqual(head2.op1,
                                                                       target_reg) and not is_op1_changed and not is_target_reg_changed:
                        addHeadinExceptList(head2)
                        continue
                    elif is_op1_offset_reference:
                        if not is_affect_range_offset_used_insert_op and not is_target_reg_changed:
                            if not is_op1_changed:
                                addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                                head2.op2 = cur.op2
                            else:
                                is_op1_used = True
                        else:
                            is_op1_used = True
                    else:
                        is_op1_used = True
                op1 = ''
                t_target_reg = ''
                if is_op1_stack_pointer:
                    op1 = (push_count > 0 and '[esp+%d' % (push_count * 4) + ']' or '[esp]')
                else:
                    op1 = cur.op1
                if is_target_reg_stack_pointer:
                    t_target_reg = (push_count > 0 and '[esp+%d' % (push_count * 4) + ']' or '[esp]')
                else:
                    t_target_reg = target_reg
                if (IsOpEqual(head2.op1, op1) and IsOpEqual(head2.op2, t_target_reg)) or (IsOpEqual(head2.op1, t_target_reg) and IsOpEqual(head2.op2, op1)):
                    if can_pattern1_change: # (mov eax,ecx / mov ecx, 39030 / xchg eax,ecx) -> mov eax, 39030
                        if not is_op1_used:
                            curHeadRemove()
                        for ea in pattern1_except_list:
                            head = GetHead(ea)
                            addHeadinExceptList(head)
                        addHeadinModifyList(head2.ea,head2.extend, 'mov', op1, target_reg_real_value)
                        break
                    else:
                        break
                elif IsOpEqual(head2.op1, op1) or IsOpEqual(head2.op2, op1):
                    break
                elif IsOpEqual(head2.op1, t_target_reg) or IsOpEqual(head2.op2, t_target_reg):
                    break
                if is_op1_offset_reference:
                    if head2_op1_reference_reg and IsNumber(head2_op1_reference_reg):
                        head2_op1_offset_int = hex2int(head2_op1_reference_reg)
                        if (op1_offset_int >= head2_op1_offset_int + 3) and (op1_offset_int <= head2_op1_offset_int - 3):
                            is_affect_range_offset_used_insert_op = True
                    if head2_op2_reference_reg and IsNumber(head2_op2_reference_reg):
                        head2_op2_offset_int = hex2int(head2_op2_reference_reg)
                        if (op1_offset_int >= head2_op2_offset_int + 3) and (op1_offset_int <= head2_op2_offset_int - 3):
                            is_affect_range_offset_used_insert_op = True
                if head2_op1_reference_reg:
                    if not IsNumber(head2_op1_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
                if head2_op2_reference_reg:
                    if not IsNumber(head2_op2_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_insert_op = True
            elif head2.mnem == 'call':
                if not is_op1_used and not op1_reference_reg and not IsNumber(cur.op1):
                    curHeadRemove()
                    break
                if type_original_reg:
                    pattern_type_original_reg_encounter_call = True
                    is_target_reg_changed = True
                    is_target_reg_insert_value = False
            elif head2.mnem == 'cmp':
                if not is_op1_stack_pointer:
                    if IsOpEqual(head2.op2, cur.op1):
                        compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
                        if is_op1_offset_reference:
                            if not is_affect_range_offset_used_insert_op and not is_not_number_offset_ref_used_insert_op and not is_target_reg_changed:
                                if not is_op1_changed:
                                    addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                                    head2.op2 = cur.op2
                                else:
                                    is_op1_used = True
                            else:
                                is_op1_used = True
                        elif is_op1_identify_real_value:
                            if IsWordRegister(head2.op2):
                                if not IsOpWord(head2.op1):
                                    head2.op1 = 'word ptr %s' % head2.op1
                            elif IsLowHighRegister(head2.op2) or IsLowLowRegister(head2.op2):
                                if not IsOpByte(head2.op1):
                                    head2.op1 = 'byte ptr %s' % head2.op1
                            addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, cur.op2)
                            head2.op2 = cur.op2
                        else:
                            is_op1_used = True
                    if IsOpEqual(head2.op1, cur.op1):
                        is_op1_used = True
                    elif IsPointSameRegister(head2.op1, cur.op1):
                        is_op1_used = True
                    elif IsPointSameRegInReferenceReg(head2.op1, cur.op1):
                        is_op1_used = True
                if not is_target_reg_stack_pointer:
                    if IsOpEqual(head2.op1, target_reg):
                        is_target_reg_used = True
                    elif IsPointSameRegister(head2.op1, target_reg):
                        is_target_reg_used = True
                    elif IsPointSameRegInReferenceReg(head2.op1, target_reg):
                        is_target_reg_used = True
                if head2_op1_reference_reg:
                    if not IsNumber(head2_op1_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
                if head2_op2_reference_reg:
                    if not IsNumber(head2_op2_reference_reg) and not StrFind(head2_op1_reference_reg, 'esp'):
                        is_not_number_offset_ref_used_op = True
            elif head2.mnem == 'cmpxchg':
                addHeadinExceptList(head2)
                zero_flag = True
def movzx_deob():
    global cur
    op1_reference_reg = GetReferenceReg(cur.op1)
    if op1_reference_reg and not StrFind(op1_reference_reg, 'esp'):
        reference_offset = GetRegValue(op1_reference_reg)
        if not reference_offset == -1:
            cur.op1 = '[%s]' % reference_offset
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                    cur.ea, cur.mnem, cur.op1, cur.op2))
    op1_reference_reg = GetReferenceReg(cur.op1)

    op2_reference_reg = GetReferenceReg(cur.op2)
    if op2_reference_reg and not StrFind(op2_reference_reg, 'esp'):
        if not IsNumber(op2_reference_reg):
            reference_offset = GetRegValue(op2_reference_reg)
            if not reference_offset == -1:
                if IsOpWord(cur.op2):
                    cur.op2 = 'word ptr [%s]' % reference_offset
                elif IsOpByte(cur.op2):
                    cur.op2 = 'byte ptr [%s]' % reference_offset
                else:
                    cur.op2 = 'word ptr [%s]' % reference_offset
                if cur.extend:
                    print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                        cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                else:
                    print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                        cur.ea, cur.mnem, cur.op1, cur.op2))
    op2_reference_reg = GetReferenceReg(cur.op2)

    if op2_reference_reg:
        if IsNumber(op2_reference_reg):
            value = GetOffsetDwordValueIfCan(op2_reference_reg)
            if not value == -1:
                cur.mnem = 'mov'
                if IsOpWord(cur.op2):
                    cur.op2 = int2hex(GetLowWord(value))
                elif IsOpByte(cur.op2):
                    cur.op2 = int2hex(value & 0xFF)
                if cur.extend:
                    print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                        cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                else:
                    print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                        cur.ea, cur.mnem, cur.op1, cur.op2))
                mov_deob()
    elif IsNumber(cur.op2):
        cur.mnem = 'mov'
        cur.op2 = int2hex(GetLowWord(hex2int(cur.op2)))
        if cur.extend:
            print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
        else:
            print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                cur.ea, cur.mnem, cur.op1, cur.op2))
        mov_deob()
    elif not IsNumber(cur.op2):
        value = GetRegValue(cur.op2)
        if not value == -1:
            cur.mnem = 'mov'
            cur.op2 = int2hex(GetLowWord(value))
            if cur.extend:
                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
            else:
                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                    cur.ea, cur.mnem, cur.op1, cur.op2))
            mov_deob()

def cmp_deob():
    global cur, head2, new_ins_list
    head2 = cur
    isContinue = True
    while isContinue:
        head2 = NextHead(head2)
        if not head2:
            break
        if not IsHeadinExceptList(head2):
            if head2.extend:
                print_log('\tmov first loop check(0x%x(%d)) : %s\n' % (head2.ea, head2.extend, GetDisasm(head2)))
            else:
                print_log('\tmov first loop check(0x%x) : %s\n' % (head2.ea, GetDisasm(head2)))
            if IsJump(head2.mnem):
                break
            elif head2.mnem == 'mov':
                curHeadRemove()
                break
            elif IsCalcMnem(head2.mnem):
                curHeadRemove()
                break
            elif head2.mnem == 'cmp':
                curHeadRemove()
            elif head2.mnem == 'pushf':
                op1_reference_reg = GetReferenceReg(cur.op1)
                if op1_reference_reg and not IsNumber(op1_reference_reg) and not StrFind(op1_reference_reg, 'esp'):
                    reference_offset = GetRegValue(op1_reference_reg)
                    if not reference_offset == -1:
                        if IsOpWord(cur.op1):
                            cur.op1 = 'word ptr [%s]' % reference_offset
                        elif IsOpByte(cur.op1):
                            cur.op1 = 'byte ptr [%s]' % reference_offset
                        else:
                            cur.op1 = 'dword ptr [%s]' % reference_offset
                        op1_reference_reg = GetReferenceReg(cur.op1)
                        if cur.extend:
                            print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                        else:
                            print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
                op2_reference_reg = GetReferenceReg(cur.op2)
                if op2_reference_reg and not IsNumber(op2_reference_reg) and not StrFind(op2_reference_reg, 'esp'):
                    reference_offset = GetRegValue(op2_reference_reg)
                    if not reference_offset == -1:
                        cur.op2 = '[%s]' % reference_offset
                        if cur.extend:
                            print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                                cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                        else:
                            print_log(
                                '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))
                op2_reference_reg = GetReferenceReg(cur.op2)
                if op2_reference_reg and not StrFind(op2_reference_reg, 'esp'):
                    if IsNumber(op2_reference_reg):
                        value = GetOffsetDwordValueIfCan(op2_reference_reg)
                        if not value == -1:
                            if op1_reference_reg:
                                if IsWordRegister(cur.op2):
                                    if not IsOpWord(cur.op1):
                                        cur.op1 = 'word ptr [%s]' % op1_reference_reg
                                elif IsLowHighRegister(cur.op2) or IsLowLowRegister(cur.op2):
                                    if not IsOpByte(cur.op1):
                                        cur.op1 = 'byte ptr [%s]' % op1_reference_reg
                                else:
                                    if not IsOpDword(cur.op1):
                                        cur.op1 = 'dword ptr [%s]' % op1_reference_reg
                            cur.op2 = int2hex(value)
                            op2_reference_reg = False
                            if cur.extend:
                                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                            else:
                                print_log(
                                    '\t\tcurrent target change(0x%x) : %s %s, %s\n' % (cur.ea, cur.mnem, cur.op1, cur.op2))

                '''if not IsNumber(op1_reference_reg) and cur.op2 == '0':
                    curHeadRemove()
                    addHeadinModifyList(head2.ea, head2.extend, 'push', int2hex(0x246), False)
                    break'''
                op1_value = -1
                op2_value = -1
                search_reg = cur.op1
                if IsLowBitRegister(search_reg):
                    search_reg = GetTopRegister(search_reg)
                t_index = len(new_ins_list) - 1
                while not t_index == 0:
                    head = new_ins_list[t_index]
                    if not head:
                        break
                    if head.extend:
                        print_log('\tcmp op1 check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                    else:
                        print_log('\tcmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                    if head.mnem == 'mov':
                        if IsOpEqual(head.op1, search_reg):
                            if IsNumber(head.op2):
                                op1_value = hex2int(head.op2)
                                break
                            else:
                                op1_reference_reg = GetReferenceReg(head.op2)
                                if op1_reference_reg:
                                    if IsNumber(op1_reference_reg):
                                        op1_value = GetOffsetDwordValueIfCan(op1_reference_reg)
                                break
                        elif IsLowBitSameRegister(head.op1, search_reg):
                            break
                    elif head.mnem == 'movzx':
                        if IsOpEqual(head.op1, search_reg):
                            break
                        elif IsLowBitSameRegister(head.op1, search_reg):
                            break
                    elif IsCalcMnem(head.mnem):
                        if IsOpEqual(head.op1, search_reg):
                            break
                        elif IsLowBitSameRegister(head.op1, search_reg):
                            break
                    elif head.mnem == 'pop':
                        if IsOpEqual(head.op1, search_reg):
                            break
                        elif IsLowBitSameRegister(head.op1, search_reg):
                            break
                    elif head.mnem == 'xchg':
                        if IsOpEqual(head.op1, search_reg) or IsLowBitSameRegister(head.op1, search_reg):
                            break
                        elif IsOpEqual(head.op2, search_reg) or IsLowBitSameRegister(head.op1, search_reg):
                            break
                    t_index -= 1
                if not op1_value == -1:
                    if IsWordRegister(cur.op1):
                        op1_value &= 0xFFFF
                    elif IsLowHighRegister(cur.op1):
                        op1_value &= 0xFF00
                    elif IsLowLowRegister(cur.op1):
                        op1_value &= 0xFF
                print_log('\t\tcmp op1 : 0x%x\n' % op1_value)
                if not op1_value == -1:
                    if IsNumber(cur.op2):
                        op2_value = hex2int(cur.op2)
                    else:
                        search_reg = cur.op2
                        if IsLowBitRegister(search_reg):
                            search_reg = GetTopRegister(search_reg)
                        t_index = len(new_ins_list) - 1
                        while not t_index == 0:
                            head = new_ins_list[t_index]
                            if not head:
                                break
                            if head.extend:
                                print_log('\tcmp op1 check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                            else:
                                print_log('\tcmp op1 check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                            if head.mnem == 'mov':
                                if IsOpEqual(head.op1, search_reg):
                                    if IsNumber(head.op2):
                                        op2_value = hex2int(head.op2)
                                        break
                                    else:
                                        op2_reference_reg = GetReferenceReg(head.op2)
                                        if op2_reference_reg:
                                            if IsNumber(op2_reference_reg):
                                                op2_value = GetOffsetDwordValueIfCan(op2_reference_reg)
                                        break
                                elif IsLowBitSameRegister(head.op1, search_reg):
                                    break
                            elif head.mnem == 'movzx':
                                if IsOpEqual(head.op1, search_reg):
                                    break
                                elif IsLowBitSameRegister(head.op1, search_reg):
                                    break
                            elif IsCalcMnem(head.mnem):
                                if IsOpEqual(head.op1, search_reg):
                                    break
                                elif IsLowBitSameRegister(head.op1, search_reg):
                                    break
                            elif head.mnem == 'pop':
                                if IsOpEqual(head.op1, search_reg):
                                    break
                                elif IsLowBitSameRegister(head.op1, search_reg):
                                    break
                            t_index -= 1
                        if not op2_value == -1:
                            if IsWordRegister(cur.op2):
                                op2_value &= 0xFFFF
                            elif IsLowHighRegister(cur.op2):
                                op2_value &= 0xFF00
                            elif IsLowLowRegister(cur.op2):
                                op2_value &= 0xFF
                print_log('\t\tcmp op2 : 0x%x\n' % op2_value)
                if not op1_value == -1 and not op2_value == -1:
                    zf = False #check
                    of = False #check
                    cf = False #check
                    pf = False #check
                    sf = False #check
                    af = False #check
                    sub = op1_value - op2_value
                    if sub == 0:
                        zf = True
                    if sub < 0:
                        sf = True
                        cf = True
                    if IsOpDword(cur.op1) or IsDwordRegister(cur.op1):
                        if op1_value > 0x7FFFFFFF:
                            if sub > 0 and sub <= 0x7FFFFFFF:
                                of = True
                    elif IsOpWord(cur.op1) or IsWordRegister(cur.op1):
                        if op1_value > 0x7FFF:
                            if sub > 0 and sub <= 0x7FFF:
                                of = True
                    elif IsOpByte(cur.op1) or IsLowHighRegister(cur.op1) or IsLowLowRegister(cur.op1):
                        if op1_value > 0x7F:
                            if sub > 0 and sub <= 0x7F:
                                of = True
                    count = 0
                    check_bit = 1
                    check = 0
                    parity_flag_check_sub = sub & 0xFFFFFFFF
                    while check_bit <= 0xFF:
                        check = parity_flag_check_sub & check_bit
                        if check:
                            count += 1
                        check_bit <<= 1
                    if count % 2 == 0:
                        pf = True
                    if (op1_value & 0xF) - (op2_value & 0xF) < 0:
                        af = True

                    result = 0x202
                    if zf:
                        result += 0x40
                    if of:
                        result += 0x800
                    if cf:
                        result += 0x1
                    if pf:
                        result += 0x4
                    if sf:
                        result += 0x80
                    if af:
                        result += 0x10
                    curHeadRemove()
                    addHeadinModifyList(head2.ea, head2.extend, 'push', int2hex(result), False)
                break
def cmpxchg_deob():
    global isInsert, cur, zero_flag
    curHeadRemove()
    head = NextHead(cur)
    if head.mnem == 'jz':
        zero_flag = 2
# second loop deob functions
def push_push_deob():
    global except_list, modifyList
    global isExchanged, isContinue, traceList, traceTemp, head2, cur, last_target_op_change, exchangeTarget, push_count
    global isCheckTrue, isContinue2, compare_str, head3, isExchangeEncounter, is_op1_used, can_stack_change_check
    global once_stack_change_register_encounter, is_cur_target_reg_changed, is_cur_stack_used, is_cur_op1_known_value
    can_stack_change_check = False
    once_stack_change_register_encounter = True
    if IsOpEqual(cur.op1,head2.op1):
        is_op1_used=True
    compare_str = (push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]')
    print_log('\t\tpush compare_str : %s\n' % compare_str)
    push_count += 1
    if IsOpEqual(head2.op1,compare_str):
        if not isExchangeEncounter:
            if cur.mnem == 'pushf':
                can_change = True
                traceTemp = list(traceList)
                traceTemp.pop()
                while len(traceTemp) > 1:
                    head3 = GetHead(traceTemp.pop())
                    if head3.extend:
                        print_log('\t\tcan change check trace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                    else:
                        print_log('\t\tcan change check trace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                    if IsCalcMnem(head3.mnem):
                        can_change = False
                        break
                if can_change:
                    addHeadinModifyList(head2.ea, head2.extend, 'pushf', False, False)
            elif is_cur_op1_known_value and not is_cur_target_reg_changed:
                if not StrFind(cur.op1, '[esp') and not IsOpEqual(cur.op1, 'esp'):
                    delHeadinTraceList(head2.ea,head2.extend)
                    addHeadinModifyList(head2.ea,head2.extend, 'push', cur.op1, False)
                else:
                    is_cur_stack_used = True
            isContinue = False
def push_pop_deob():
    global cur, except_list, isInsert, modifyList, is_op1_used
    global push_count, head2, isContinue, can_push_pop_remove, isPopMemoryEspEncounter, isExchangeEncounter, can_stack_change_check
    global once_stack_change_register_encounter, push_pop_late_modify_list, is_cur_target_reg_changed, is_cur_op1_known_value
    global is_cur_target_reg_known_value, cur_stack_calc_list, is_cur_stack_changed, cur_target_reg_point_reg
    global is_cur_target_reg_point_reg_changed, cur_target_reg, cur_target_reg_point_reg, esp_size_change_late_extend_list
    global deob_count, test_record, is_cur_stack_used
    cur_op1_reference_reg = GetReferenceReg(cur.op1)
    op1_reference_reg = GetReferenceReg(head2.op1)
    if push_count == 0 and cur_op1_reference_reg and not IsNumber(cur_op1_reference_reg) and not StrFind(cur.op1, 'esp'):
        can_push_pop_remove = False
    elif push_count == 0 and op1_reference_reg and not IsNumber(op1_reference_reg) and not StrFind(head2.op1, 'esp'):
        can_push_pop_remove = False
    can_stack_change_check = False
    if IsOpEqual(head2.op1, '[esp]'):
        isPopMemoryEspEncounter = True
    if push_count == 0:
        if can_push_pop_remove:
            if IsOpEqual(head2.op1, cur.op1) and not StrFind(head2.op1, 'esp'): # push esi, ~~~ , pop esi
                is_reference = GetReferenceReg(cur.op1)
                is_op1_used_insert_op = False
                is_op1_used_op2 = False
                top_reg = False
                reference_reg = False
                if not is_reference:
                    reference_reg = '[%s]' % cur.op1
                    if IsLowBitRegister(cur.op1):
                        top_reg = GetTopRegister(cur.op1)
                can_change = True
                t_push_count = 0
                traceTemp = list(traceList)
                traceTemp.pop()
                while len(traceTemp) > 1:
                    head3 = GetHead(traceTemp.pop())
                    if head3.extend:
                        print_log('\t\tcan change check trace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                    else:
                        print_log('\t\tcan change check trace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                    if IsPushMnem(head3.mnem):
                        t_push_count -= 1
                        t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                        if IsOpEqual(head3.op1, t_compare_str):
                            can_change = False
                            break
                        if IsOpEqual(head3.op1, head2.op1):
                            can_change = False
                            break
                    t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                    if head3.mnem == 'xchg':
                        if IsOpEqual(head3.op1, head2.op1) or IsOpEqual(head3.op1, head2.op1):
                            can_change = False
                            break
                    elif IsCalcMnem(head3.mnem):
                        if IsOpEqual(head3.op1, cur.op1):
                            can_change = False
                            break
                    elif head3.mnem == 'mov':
                        if IsOpEqual(head3.op1, cur.op1):
                            if is_op1_used_op2:
                                can_change = False
                                break
                            is_op1_used_insert_op = True
                    if IsOpEqual(head3.op2, t_compare_str):
                        can_change = False
                        break
                    elif StrFind(head3.op2, head2.op1):
                        if is_op1_used_insert_op:
                            can_change = False
                            break
                        is_op1_used_op2 = True
                    elif is_cur_target_reg_changed and IsOpInReferenceRegIncludeSameReg(head3.op1, cur.op1):
                        can_change = False
                        break
                    if head3.mnem == 'pop':
                        t_push_count += 1
                        if IsOpEqual(head3.op1, cur.op1):
                            can_change = False
                            break
                if can_change:
                    for info in push_pop_late_modify_list:
                        head = GetHead([info[0], info[1]])
                        addHeadinModifyList(head.ea, head.extend, head.mnem, info[2], head.op2)
                    t_push_count = 0
                    push_pop_late_modify_list = []
                    traceTemp = list(traceList)
                    traceTemp.pop()
                    is_op1_used2 = False
                    while len(traceTemp) > 1:
                        head3 = GetHead(traceTemp.pop())
                        op1 = head3.op1
                        op2 = head3.op2
                        if head3.extend:
                            print_log('\t\tmodify trace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                        else:
                            print_log('\t\tmodify trace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                        if IsOpEqual(head3.op2, head2.op1):
                            is_op1_used_op2 = True
                        elif IsPointSameRegister(head3.op2, head2.op1):
                            is_op1_used_op2 = True
                        elif IsOpInReferenceRegIncludeSameReg(head3.op2, head2.op1):
                            is_op1_used_op2 = True
                        if IsPushMnem(head3.mnem):
                            t_push_count -= 1
                            if IsOpEqual(head3.op1, head2.op1):
                                is_op1_used_op2 = True
                            elif IsPointSameRegister(head3.op1, head2.op1):
                                is_op1_used_op2 = True
                            elif IsOpInReferenceRegIncludeSameReg(head3.op1, head2.op1):
                                is_op1_used_op2 = True
                        elif head3.mnem == 'mov':
                            if IsOpEqual(head3.op1, head2.op1):
                                if not is_op1_used_op2:
                                    addHeadinExceptList(head3)
                                    delHeadinTraceList(head3.ea, head3.extend)
                                continue
                        elif head3.mnem == 'movzx':
                            if IsOpEqual(head3.op1, head2.op1):
                                if not is_op1_used_op2:
                                    addHeadinExceptList(head3)
                                    delHeadinTraceList(head3.ea, head3.extend)
                                continue
                        elif IsCalcMnem(head3.mnem):
                            if IsOpEqual(head3.op1, head2.op1):
                                if not is_op1_used_op2:
                                    addHeadinExceptList(head3)
                                    delHeadinTraceList(head3.ea, head3.extend)
                                continue
                            if head3.mnem == 'add':
                                if head3.op1 == 'esp':
                                    t_push_count += 1
                                elif head3.op2 == 'esp':
                                    addExtendHeadinHead(head3.ea, 'sub', head3.op1, '4')
                            elif head3.mnem == 'sub':
                                if head3.op1 == 'esp':
                                    t_push_count -= 1
                        isCheckTrue = False
                        if head3.op1 and StrFind(head3.op1, '[esp'):
                            t_num = GetEspNumber(head3.op1)
                            if (t_num / 4) > t_push_count:
                                t_num -= 4
                                if t_num > 0:
                                    op1 = '[esp+%s]' % int2hex(t_num)
                                elif t_num == 0:
                                    op1 = '[esp]'
                                elif t_num < 0:
                                    op1 = '[esp%s]' % int2hex(t_num)
                                isCheckTrue = True
                        if head3.op2 and StrFind(head3.op2, '[esp'):
                            t_num = GetEspNumber(head3.op2)
                            if (t_num / 4) > t_push_count:
                                t_num -= 4
                                if t_num > 0:
                                    op2 = '[esp+%s]' % int2hex(t_num)
                                elif t_num == 0:
                                    op2 = '[esp]'
                                elif t_num < 0:
                                    op2 = '[esp%s]' % int2hex(t_num)
                                isCheckTrue = True
                        if isCheckTrue:
                            addHeadinModifyList(head3.ea, head3.extend, head3.mnem, op1, op2)
                        if head3.mnem == 'pop':
                            t_push_count += 1
                    addHeadinExceptList(head2)
                    curHeadRemove()
                    if StrFind(head2.op1, '[esp]'):
                        curHeadRepair()
                        cur.mnem = 'mov'
                        cur.op2 = cur.op1
                        cur.op1 = '[esp]'
                    for head in esp_size_change_late_extend_list:
                        if not IsHeadinExceptList(head):
                            addExtendHeadinHead(head.ea, 'sub', head.op1, '4')
            elif StrFind(head2.op1, '[esp]'): # pop dword ptr [esp]
                can_change = True
                can_change2 = False
                t_push_count = 0
                t_push_count2 = 0
                late_except_list = []
                change_first_head = False
                change_last_head = False
                esp_n = GetEspNumber(head2.op1)
                if not esp_n == -1:
                    t_push_count2 = (esp_n / 4) + 1
                traceTemp = list(traceList)
                traceTemp.pop()
                while len(traceTemp) > 1:
                    head3 = GetHead(traceTemp.pop())
                    if head3.extend:
                        print_log('\t\tcan change check trace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                    else:
                        print_log('\t\tcan change check trace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                    if IsPushMnem(head3.mnem):
                        t_push_count -= 1
                        t_push_count2 -= 1
                        t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                        t_compare_str2 = t_push_count2 > 0 and '[esp+%s' % int2hex(t_push_count2 * 4) + ']' or '[esp]'
                        if IsOpEqual(head3.op1, t_compare_str2):
                            if change_first_head:
                                can_change = False
                                break
                            else:
                                change_last_head = True
                        elif IsOpEqual(head3.op1, t_compare_str):
                            can_change = False
                            break
                    t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                    t_compare_str2 = t_push_count2 > 0 and '[esp+%s' % int2hex(t_push_count2 * 4) + ']' or '[esp]'
                    if head3.mnem == 'mov':
                        if IsOpEqual(head3.op1, cur.op1):
                            if IsOpEqual(head3.op2, t_compare_str2):
                                if not (change_first_head or change_last_head):
                                    late_except_list.append([head3.ea, head3.extend])
                                    can_change = False
                                    can_change2 = True
                                    break
                                else:
                                    can_change = False
                                    break
                            else:
                                change_first_head = True
                    elif head3.mnem == 'movzx':
                        if IsOpEqual(head3.op1, cur.op1):
                            if IsOpEqual(head3.op2, t_compare_str2):
                                if not (change_first_head or change_last_head):
                                    late_except_list.append([head3.ea, head3.extend])
                                    can_change = False
                                    can_change2 = True
                                    break
                                else:
                                    can_change = False
                                    break
                            else:
                                change_first_head = True
                    elif IsCalcMnem(head3.mnem):
                        if IsOpEqual(head3.op1, cur.op1):
                            change_first_head = True
                    if IsOpEqual(head3.op2, t_compare_str):
                        can_change = False
                        break
                    elif IsOpEqual(head3.op2, t_compare_str2):
                        if change_first_head:
                            can_change = False
                            break
                        else:
                            change_last_head = True
                    elif IsOpEqual(head3.op2, head2.op1):
                        can_change = False
                        break
                    if head3.mnem == 'pop':
                        if IsOpEqual(head3.op1, t_compare_str):
                            can_change = False
                            break
                        t_push_count += 1
                        t_push_count2 += 1
                        if IsOpEqual(head3.op1, cur.op1):
                            change_first_head = True
                if can_change:
                    for info in push_pop_late_modify_list:
                        head = GetHead([info[0], info[1]])
                        addHeadinModifyList(head.ea, head.extend, head.mnem, info[2], head.op2)
                    t_push_count = 0
                    push_pop_late_modify_list = []
                    traceTemp = list(traceList)
                    traceTemp.pop()
                    while len(traceTemp) > 1:
                        head3 = GetHead(traceTemp.pop())
                        op1 = head3.op1
                        op2 = head3.op2
                        if head3.extend:
                            print_log('\t\tmodify trace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                        else:
                            print_log('\t\tmodify trace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                        if IsPushMnem(head3.mnem):
                            t_push_count -= 1
                        isCheckTrue = False
                        if head3.op1 and StrFind(head3.op1, '[esp'):
                            t_num = GetEspNumber(head3.op1)
                            if (t_num / 4) > t_push_count:
                                t_num -= 4
                                if t_num > 0:
                                    op1 = '[esp+%s]' % int2hex(t_num)
                                elif t_num == 0:
                                    op1 = '[esp]'
                                elif t_num < 0:
                                    op1 = '[esp%s]' % int2hex(t_num)
                                isCheckTrue = True
                        if head3.op2 and StrFind(head3.op2, '[esp'):
                            t_num = GetEspNumber(head3.op2)
                            if (t_num / 4) > t_push_count:
                                t_num -= 4
                                if t_num > 0:
                                    op2 = '[esp+%s]' % int2hex(t_num)
                                elif t_num == 0:
                                    op2 = '[esp]'
                                elif t_num < 0:
                                    op2 = '[esp%s]' % int2hex(t_num)
                                isCheckTrue = True
                        if isCheckTrue:
                            addHeadinModifyList(head3.ea, head3.extend, head3.mnem, op1, op2)
                        if head3.mnem == 'pop':
                            t_push_count += 1
                    if not change_last_head:
                        addHeadinExceptList(head2)
                        if StrFind(head2.op1, '[esp]'):
                            cur.mnem = 'mov'
                            cur.op2 = cur.op1
                            cur.op1 = '[esp]'
                            if cur.extend:
                                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                            else:
                                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                                    cur.ea, cur.mnem, cur.op1, cur.op2))
                    else:
                        curHeadRemove()
                        addHeadinModifyList(head2.ea, head2.extend, 'mov', '[esp]', cur.op1)
                        for head in esp_size_change_late_extend_list:
                            addExtendHeadinHead(head.ea, 'sub', head.op1, '4')
                elif can_change2:
                    curHeadRemove()
                    for info in late_except_list:
                        head = GetHead(info)
                        addHeadinExceptList(head)
                    addHeadinModifyList(head2.ea, head2.extend, 'xchg', cur.op1, head2.op1)
                    for head in esp_size_change_late_extend_list:
                        if not IsHeadinExceptList(head):
                            addExtendHeadinHead(head.ea, 'sub', head.op1, '4')
            elif IsOpEqual(head2.op1, 'esp'):
                isContinue2 = True
                t_push_count = push_count
                can_change = False
                stack_change_value = 0
                target_reg = False
                is_err = False
                late_except_list = []
                late_extend_list = []
                traceTemp = list(traceList)
                traceTemp.pop()
                while isContinue2 and len(traceTemp) > 1:
                    head3 = GetHead(traceTemp.pop())
                    if head3.extend:
                        print_log('\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                    else:
                        print_log('\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                    if IsPushMnem(head3.mnem):
                        t_push_count -= 1
                    t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                    if head3.mnem == 'mov':
                        if IsOpEqual(head3.op1, t_compare_str):  # compare_str don't modify t_compare_str
                            if IsOpEqual(head3.op2, 'esp'):
                                late_except_list.append([head3.ea, head3.extend])
                                can_change = True
                                break
                            else:
                                target_reg = head3.op2
                                late_except_list.append([head3.ea, head3.extend])
                        elif target_reg and IsOpEqual(head3.op1, target_reg):
                            if IsOpEqual(head3.op2, 'esp'):
                                late_extend_list.append([head3.ea, 'sub', head3.op1, '4'])
                                can_change = True
                                break
                            else:
                                break
                        elif IsOpEqual(head3.op2, 'esp'):
                            late_extend_list.append([head3.ea, 'sub', head3.op1, '4'])
                    elif head3.mnem == 'movzx':
                        if IsOpEqual(head3.op1, t_compare_str):  # compare_str don't modify t_compare_str
                            break
                        elif target_reg and IsOpEqual(head3.op1, target_reg):
                            break
                        elif IsOpEqual(head3.op2, 'esp'):
                            break
                    elif IsCalcMnem(head3.mnem):
                        if target_reg and IsOpEqual(head3.op1, target_reg):
                            if not IsNumber(head3.op2):
                                is_err = True
                                can_change = False
                                break
                            if head3.mnem == 'add':
                                stack_change_value += hex2int(head3.op2)
                            elif head3.mnem == 'sub':
                                stack_change_value -= hex2int(head3.op2)
                            elif head3.mnem == 'inc':
                                stack_change_value += 1
                            elif head3.mnem == 'dec':
                                stack_change_value -= 1
                            else:
                                break
                        elif not target_reg and IsOpEqual(cur.op1, 'esp') and IsOpEqual(head3.op1, t_compare_str):
                            if not IsNumber(head3.op2):
                                is_err = True
                                can_change = False
                                break
                            late_except_list.append([head3.ea, head3.extend])
                            if head3.mnem == 'add':
                                stack_change_value += hex2int(head3.op2)
                            elif head3.mnem == 'sub':
                                stack_change_value -= hex2int(head3.op2)
                            elif head3.mnem == 'inc':
                                stack_change_value += 1
                            elif head3.mnem == 'dec':
                                stack_change_value -= 1
                            else:
                                is_err = True
                                break
                        elif IsOpEqual(head3.op1, t_compare_str):
                            can_change = False
                            break
                    elif head3.mnem == 'xchg':
                        if target_reg and (IsOpEqual(head3.op1, target_reg) or IsOpEqual(head3.op2, target_reg)):
                            break
                    elif head3.mnem == 'pop':
                        t_push_count += 1
                        if target_reg and IsOpEqual(head3.op1, target_reg):
                            break
                if not target_reg and IsOpEqual(cur.op1, 'esp') and not is_err:
                    can_change = True
                if can_change:
                    is_cur_remove = False
                    if target_reg:
                        stack_change_value -= 4
                    if stack_change_value > 0:
                        curHeadRemove()
                        is_cur_remove = True
                        for info in late_except_list:
                            head = GetHead(info)
                            addHeadinExceptList(head)
                            delHeadinTraceList(head.ea, head.extend)
                        addHeadinModifyList(head2.ea, head2.extend, 'add', 'esp', int2hex(stack_change_value))
                    elif stack_change_value == -4:
                        addHeadinExceptList(head2)
                        delHeadinTraceList(head2.ea, head2.extend)
                    elif stack_change_value < -4:
                        stack_change_value = ~stack_change_value + 1
                        stack_change_value -= 4
                        addHeadinModifyList(head2.ea, head2.extend, 'sub', 'esp', int2hex(stack_change_value))
                    elif stack_change_value == 0:
                        curHeadRemove()
                        is_cur_remove = True
                        for info in late_except_list:
                            head = GetHead(info)
                            addHeadinExceptList(head)
                            delHeadinTraceList(head.ea, head.extend)
                        addHeadinExceptList(head2)
                        delHeadinTraceList(head2.ea, head2.extend)
                    if is_cur_remove:
                        t_push_count = 0
                        traceTemp = list(traceList)
                        traceTemp.pop()
                        while len(traceTemp) > 1:
                            head3 = GetHead(traceTemp.pop())
                            if head3.extend:
                                print_log('\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                            else:
                                print_log('\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                            if IsPushMnem(head3.mnem):
                                t_push_count -= 1
                            t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                            if head3.mnem == 'mov':
                                if IsOpEqual(head3.op1, t_compare_str):
                                    addHeadinExceptList(head3)
                            elif head3.mnem == 'movzx':
                                if IsOpEqual(head3.op1, t_compare_str):
                                    addHeadinExceptList(head3)
                            elif IsCalcMnem(head3.mnem):
                                if IsOpEqual(head3.op1, t_compare_str):
                                    addHeadinExceptList(head3)
                            elif head3.mnem == 'pop':
                                t_push_count += 1
                        for head in esp_size_change_late_extend_list:
                            if not IsHeadinExceptList(head):
                                addExtendHeadinHead(head.ea, 'sub', head.op1, '4')
                    isContinue = False
            else:
                if not cur.mnem == 'pushf' and not isExchangeEncounter and not once_stack_change_register_encounter and is_cur_op1_known_value:
                    can_change = True
                    head2_op1_reference_reg = GetReferenceReg(head2.op1)
                    if head2_op1_reference_reg:
                        if not IsNumber(head2_op1_reference_reg):
                            can_change = False
                    if can_change:
                        t_push_count = 0
                        t_push_count2 = 0
                        change_first_head = False
                        change_last_head = False
                        late_modify_list = []
                        traceTemp = list(traceList)
                        traceTemp.pop()
                        while len(traceTemp) > 1:
                            head3 = GetHead(traceTemp.pop())
                            if head3.extend:
                                print_log('\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                            else:
                                print_log('\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                            if IsPushMnem(head3.mnem):
                                t_push_count -= 1
                                if IsOpEqual(head3.op1, head2.op1):
                                    if change_first_head:
                                        can_change = False
                                        break
                                    change_last_head = True
                            t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                            t_compare_str2 = t_push_count2 > 0 and '[esp+%s' % int2hex(
                                t_push_count2 * 4) + ']' or '[esp]'
                            if head3.mnem == 'mov':
                                if IsOpEqual(head3.op1, cur.op1):
                                    if change_last_head:
                                        can_change = False
                                        break
                                    change_first_head = True
                                elif IsLowBitSameRegister(head3.op1, cur.op1):
                                    if change_last_head:
                                        can_change = False
                                        break
                                    change_first_head = True
                                if IsOpEqual(head3.op1, head2.op1):
                                    if change_first_head:
                                        can_change = False
                                        break
                                    change_last_head = True
                            elif head3.mnem == 'movzx':
                                if IsOpEqual(head3.op1, cur.op1):
                                    if change_last_head:
                                        can_change = False
                                        break
                                    change_first_head = True
                                elif IsLowBitSameRegister(head3.op1, cur.op1):
                                    if change_last_head:
                                        can_change = False
                                        break
                                    change_first_head = True
                                if IsOpEqual(head3.op1, head2.op1):
                                    if change_first_head:
                                        can_change = False
                                        break
                                    change_last_head = True
                            elif IsCalcMnem(head3.mnem):
                                if IsOpEqual(head3.op1, cur.op1):
                                    if change_last_head:
                                        can_change = False
                                        break
                                    change_first_head = True
                                elif IsLowBitSameRegister(head3.op1, cur.op1):
                                    if change_last_head:
                                        can_change = False
                                        break
                                    change_first_head = True
                                if IsOpEqual(head3.op1, head2.op1):
                                    if change_first_head:
                                        can_change = False
                                        break
                                    change_last_head = True
                            elif head3.mnem == 'pop':
                                t_push_count += 1
                            if IsOpEqual(head3.op1, t_compare_str):
                                if change_last_head:
                                    can_change = False
                                    break
                                change_first_head = True
                                late_modify_list.append([head3.ea, head3.extend, 0])
                            elif IsOpEqual(head3.op2, t_compare_str):
                                if change_last_head:
                                    can_change = False
                                    break
                                change_first_head = True
                                late_modify_list.append([head3.ea, head3.extend, 1])
                            if IsOpEqual(head3.op2, head2.op1):
                                if change_first_head:
                                    can_change = False
                                    break
                                change_last_head = True
                    if can_change:
                        if change_last_head:
                            curHeadRemove()
                            addHeadinModifyList(head2.ea, head2.extend, 'mov', head2.op1, cur.op1)
                        elif change_first_head:
                            cur.mnem = 'mov'
                            cur.op2 = cur.op1
                            cur.op1 = head2.op1
                            addHeadinExceptList(head2)
                            if cur.extend:
                                print_log('\t\tcurrent target change(0x%x(%d)) : %s %s, %s\n' % (
                                    cur.ea, cur.extend, cur.mnem, cur.op1, cur.op2))
                            else:
                                print_log('\t\tcurrent target change(0x%x) : %s %s, %s\n' % (
                                    cur.ea, cur.mnem, cur.op1, cur.op2))
                            for info in late_modify_list:
                                head=GetHead([info[0], info[1]])
                                if info[2]==0:
                                    addHeadinModifyList(head.ea, head.extend, head.mnem, cur.op1, head.op2)
                                else:
                                    addHeadinModifyList(head.ea, head.extend, head.mnem, head.op1, cur.op1)
                            late_modify_list = []
                        else:
                            curHeadRemove()
                            addHeadinModifyList(head2.ea, head2.extend, 'mov', head2.op1, cur.op1)
                        t_push_count = 0
                        traceTemp = list(traceList)
                        traceTemp.pop()
                        while len(traceTemp) > 1:
                            isCheckTrue = False
                            head3 = GetHead(traceTemp.pop())
                            op1 = head3.op1
                            op2 = head3.op2
                            if head3.extend:
                                print_log('\t\ttrace (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                            else:
                                print_log('\t\ttrace (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                            if IsPushMnem(head3.mnem):
                                t_push_count -= 1
                            if StrFind(head3.op1, '[esp'):
                                t_num = GetEspNumber(head3.op1)
                                if (t_num / 4) > t_push_count:
                                    t_num -= 4
                                    if t_num > 0:
                                        op1 = '[esp+%s]' % int2hex(t_num)
                                    elif t_num == 0:
                                        op1 = '[esp]'
                                    elif t_num < 0:
                                        op1 = '[esp%d]' % int2hex(t_num)
                                    isCheckTrue = True
                            if StrFind(head3.op2, '[esp'):
                                t_num = GetEspNumber(head3.op2)
                                if (t_num / 4) > t_push_count:
                                    t_num -= 4
                                    if t_num > 0:
                                        op2 = '[esp+%d]' % int2hex(t_num)
                                    elif t_num == 0:
                                        op2 = '[esp]'
                                    elif t_num < 0:
                                        op2 = '[esp%d]' % int2hex(t_num)
                                    isCheckTrue = True
                            if isCheckTrue:
                                addHeadinModifyList(head3.ea, head3.extend, head3.mnem, op1, op2)
                            if head3.mnem == 'pop':
                                t_push_count += 1
                        for head in esp_size_change_late_extend_list:
                            if not IsHeadinExceptList(head):
                                addExtendHeadinHead(head.ea, 'sub', head.op1, '4')
        isContinue = False
    else:
        push_count -= 1
        compare_str = push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]'
        if cur_target_reg_point_reg and not is_cur_target_reg_point_reg_changed and IsOpEqual(head2.op1,cur_target_reg_point_reg):
            is_cur_target_reg_point_reg_changed = True
        if IsOpEqual(head2.op1, 'esp'):
            isContinue = False
        if IsOpEqual(head2.op1, compare_str):
            is_cur_op1_known_value = False
            is_cur_stack_changed = False
            is_cur_target_reg_known_value = False
            cur_target_reg = False
            cur_target_reg_point_reg = False
            is_cur_target_reg_point_reg_changed = False
            cur_stack_calc_list = []
            is_cur_stack_used = True
        elif IsOpEqual(head2.op1, cur.op1):
            is_cur_target_reg_changed = True
            is_op1_used = True
        elif StrFind(cur.op1, head2.op1):
            is_cur_target_reg_changed = True
            is_cur_target_reg_known_value = False
        elif IsOpEqual(head2.op1, cur_target_reg_point_reg):
            is_cur_target_reg_point_reg_changed = True
    once_stack_change_register_encounter = True
def push_mov_deob():
    global cur, except_list, isInsert
    global isContinue, isExchanged, compare_str, exchangeTarget, push_count, head2, isContinue2, can_push_pop_remove
    global traceList, traceTemp, head3, last_target_op_change, head3, modifyList, isExchangeEncounter, isPopMemoryEspEncounter
    global org_push_reg_mnem, push_mov_late_except_list, is_op1_used, can_stack_change_check
    global once_stack_change_register_encounter, last_target_push_count, traceList2, reserve_esp_modify_list
    global push_pop_late_modify_list, is_cur_op1_known_value, is_cur_target_reg_changed
    global cur_target_reg_point_reg, cur_target_reg, cur_stack_calc_list, is_cur_target_reg_known_value, is_cur_stack_changed
    global is_cur_target_reg_point_reg_changed, is_cur_stack_used, esp_size_change_late_extend_list

    reserve_esp_count = 0
    compare_str = push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]'
    print_log('\t\tmov compare_str : %s\n' % compare_str)
    if IsOpEqual(cur.op1, head2.op2) and not IsOpEqual(head2.op1, head2.op2):
        is_op1_used = True
    if IsOpEqual(head2.op1, compare_str):
        if not is_cur_stack_used:
            cur_target_reg = head2.op2
            cur_stack_calc_list = []
            cur_target_reg_point_reg = False
            is_cur_target_reg_known_value = True
            is_cur_stack_changed = False
            if head2.op2 == 'esp':  # push 34859443 / mov [esp], esp
                cur_stack_calc_list.append(['sub', cur_target_reg, int2hex(push_count * 4)])
                cur_target_reg_point_reg = False
                is_cur_target_reg_point_reg_changed = False
                is_cur_stack_changed = True
                reserve_esp_count = push_count + 1
                if not isExchangeEncounter:
                    t_push_count = push_count
                    can_change = True
                    change_list = []
                    traceTemp = list(traceList)
                    traceTemp.pop()
                    while len(traceTemp) > 1:
                        head3 = GetHead(traceTemp.pop())
                        if head3.extend:
                            print_log('\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                        else:
                            print_log('\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                        if head3.mnem == 'mov':
                            t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                            if IsOpEqual(head3.op1, t_compare_str):
                                can_change = False
                                break
                        elif head3.mnem == 'movzx':
                            t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                            if IsOpEqual(head3.op1, t_compare_str):
                                can_change = False
                                break
                        elif head3.mnem == 'add':
                            t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                            if IsOpEqual(head3.op1, t_compare_str):
                                if IsNumber(head3.op2):
                                    change_list.append([head3.ea, head3.extend])
                                else:
                                    can_change = False
                                    break
                            elif head3.op1 == 'esp':
                                if not IsNumber(head3.op2):
                                    can_change = False
                                    break
                                else:
                                    t_push_count += GetEspNumber(head3.op2) / 4
                        elif head3.mnem == 'sub':
                            t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                            if IsOpEqual(head3.op1, t_compare_str):
                                if IsNumber(head3.op2):
                                    change_list.append([head3.ea, head3.extend])
                                else:
                                    can_change = False
                                    break
                            elif head3.op1 == 'esp':
                                if not IsNumber(head3.op2):
                                    can_change = False
                                    break
                                else:
                                    t_push_count -= GetEspNumber(head3.op2) / 4
                        elif IsPushMnem(head3.mnem):
                            t_push_count -= 1
                        elif head3.mnem == 'pop':
                            t_push_count += 1
                    if can_change:
                        cur.op1 = 'esp'
                        if cur.extend:
                            print_log('\t\tcurrent target change(0x%x(%d)) : %s %s\n' % (
                                cur.ea, cur.extend, cur.mnem, cur.op1))
                        else:
                            print_log('\t\tcurrent target change(0x%x) : %s %s\n' % (cur.ea, cur.mnem, cur.op1))
                        for info in change_list:
                            head = GetHead(info)
                            if not (head.ea == cur.ea and head.extend):
                                addHeadinExceptList(head)
                        addExtendHeadinHead(cur.ea, 'sub', '[esp]', int2hex(reserve_esp_count * 4))
                        push_pop_late_modify_list.append([cur.ea, 1, cur.op1])
                        t_num = GetIndexHeadInfoList([cur.ea, cur.extend], traceList) + 1
                        traceList.insert(t_num, [cur.ea, True])
                        addHeadinExceptList(head2)
                        delHeadinTraceList(head2.ea, head2.extend)
            else:
                isContinue2 = True
                can_change = True
                change_op = False
                is_op1_used2 = False
                late_except_list = []
                late_extend_list = []
                t_push_count = push_count
                t_pop_count = 0
                traceTemp = list(traceList)
                traceTemp.pop()
                while isContinue2 and len(traceTemp) > 1:
                    head3 = GetHead(traceTemp.pop())
                    if head3.extend:
                        print_log('\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                    else:
                        print_log('\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                    if IsPushMnem(head3.mnem):
                        t_push_count -= 1
                        t_pop_count += 1
                        t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                        if IsOpEqual(head3.op1, t_compare_str):
                            can_change = False
                            break
                    t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                    if IsOpEqual(head3.op2, t_compare_str):
                        can_change = False
                        break
                    if head3.ea == cur.ea and head3.extend == cur.extend:
                        isContinue2 = False
                    elif head3.mnem == 'pop':
                        t_push_count += 1
                        t_pop_count -= 1
                        if IsOpEqual(head3.op1, head2.op2):
                            can_change = False
                            break
                    elif head3.mnem == 'mov':
                        if IsOpEqual(head3.op1, head2.op2):
                            change_op = head3.op2
                            if StrFind(change_op, '[esp'):
                                t_num = GetEspNumber(change_op)
                                push_count2 = (t_num / 4) + t_pop_count
                                if push_count2 < push_count:
                                    isContinue3 = True
                                    temp_count = 0
                                    traceTemp2 = list(traceTemp)
                                    while isContinue3 and len(traceTemp2) > 1:
                                        head = GetHead(traceTemp2.pop())
                                        if head.extend:
                                            print_log('\t\t\ttrace  (0x%x(%d)) : %s\n' % (
                                            head.ea, head.extend, GetDisasm(head)))
                                        else:
                                            print_log('\t\t\ttrace  (0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                                        if IsPushMnem(head.mnem):
                                            temp_count += 1
                                            if temp_count == (push_count2 + 1):
                                                if IsNumber(head.op2):
                                                    change_op = head.op1
                                                else:
                                                    can_change = False
                                                break
                                        elif head.mnem == 'pop':
                                            temp_count -= 1
                                        elif head.mnem == 'add' and head.op2 == '4':
                                            temp_count -= 1
                                        elif head.mnem == 'sub' and head.op2 == '4':
                                            temp_count += 1
                                else:
                                    t_num -= (push_count * 4)
                                    t_num -= 4
                                    print_log('\t\t\t push count : %s / result : %s\n' % (push_count, t_num))
                                    if t_num > 0:
                                        change_op = '[esp+%s]' % int2hex(t_num)
                                    elif t_num == 0:
                                        change_op = '[esp]'
                                    elif t_num < 0:
                                        change_op = '[esp%d]' % int2hex(t_num)
                            elif change_op == 'esp':
                                late_extend_list.append(['sub', 'dword ptr [esp]', int2hex((t_push_count + 1) * 4)])
                            elif not GetReferenceReg(change_op) and not IsNumber(change_op):
                                traceTemp2 = list(traceList)
                                i = FindIndexinList(traceList, head3.ea, head3.extend) + 1
                                while i <= len(traceTemp2) - 1:
                                    head = GetHead(traceTemp2[i])
                                    if head.extend:
                                        print_log('\t\t\t\ttrace  (0x%x(%d)) : %s\n' % (
                                            head.ea, head.extend, GetDisasm(head)))
                                    else:
                                        print_log('\t\t\t\ttrace  (0x%x) : %s\n' % (head.ea, GetDisasm(head)))
                                    if head.mnem == 'pop':
                                        if IsPointSameRegister(head.op1, change_op):
                                            can_change = False
                                            break
                                    elif head.mnem == 'mov':
                                        if IsPointSameRegister(head.op1, change_op):
                                            can_change = False
                                            break
                                    elif head.mnem == 'movzx':
                                        if IsPointSameRegister(head.op1, change_op):
                                            can_change = False
                                            break
                                    elif IsCalcMnem(head.mnem):
                                        if IsPointSameRegister(head.op1, change_op):
                                            can_change = False
                                            break
                                    elif head.mnem == 'xchg':
                                        if IsPointSameRegister(head.op1, change_op) or IsPointSameRegister(head.op2, change_op):
                                            can_change = False
                                            break
                                    i += 1
                    elif head3.mnem == 'movzx':
                        if IsOpEqual(head3.op1, head2.op2):
                            can_change = False
                            isContinue2 = False
                    elif head3.mnem == 'xchg':
                        isContinue2 = False
                        can_change = False
                    elif IsCalcMnem(head3.mnem):
                        if IsOpEqual(head3.op1, head2.op2):
                            can_change = False
                            is_cur_op1_known_value = False
                            isContinue2 = False
                if not is_op1_used2:
                    if can_change:
                        for info in push_pop_late_modify_list:
                            if IsOpEqual(info[2], cur.op1):
                                push_pop_late_modify_list.remove(info)
                        cur.mnem = 'push'
                        if change_op:
                            cur.op1 = change_op
                        elif StrFind(head2.op2, '[esp'):
                            t_num = GetEspNumber(head2.op2)-(push_count * 4)
                            t_num -= 4
                            change_op = t_num > 0 and '[esp+%s' % int2hex(t_num) + ']' or '[esp]'
                            cur.op1 = change_op
                        else:
                            cur.op1 = head2.op2
                        last_target_op_change = [head2.ea, head2.extend]
                        print_log('\t\tchange cur : %s %s\n' % (cur.mnem, cur.op1))
                        for info in late_extend_list:
                            t_num = GetIndexHeadInfoList([cur.ea, cur.extend], traceList) + 1
                            t_num2 = GetExtendHeadCount(cur.ea)
                            addExtendHeadinHead(cur.ea, info[0], info[1], info[2])
                            traceList.insert(t_num + t_num2, [cur.ea, t_num2 + 1])
                        addHeadinExceptList(head2)
                        for head in push_mov_late_except_list:
                            addHeadinExceptList(head)
                            delHeadinTraceList(head.ea, head.extend)
                        push_mov_late_except_list = []
                        delHeadinTraceList(head2.ea, head2.extend)
        else:
            cur_target_reg = head2.op2
            cur_stack_calc_list = []
            cur_target_reg_point_reg = False
            is_cur_target_reg_known_value = True
            is_cur_stack_changed = False
    elif IsOpEqual(head2.op2, compare_str):
        check1 = True
        check2 = True
        if not isExchangeEncounter and not isPopMemoryEspEncounter:
            if IsOpEqual(head2.op1, 'esp'):
                isContinue2 = True
                t_push_count = push_count
                can_change = False
                is_err = False
                stack_change_value = 0
                target_reg = False
                late_except_list = []
                traceTemp = list(traceList)
                traceTemp.pop()
                if is_cur_stack_used:
                    isContinue2 = False
                while isContinue2 and len(traceTemp) > 1:
                    head3 = GetHead(traceTemp.pop())
                    if head3.extend:
                        print_log('\t\tcan change check trace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                    else:
                        print_log('\t\tcan change check trace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                    if IsPushMnem(head3.mnem):
                        t_push_count -= 1
                    t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                    if head3.mnem == 'mov':
                        if IsOpEqual(head3.op1, t_compare_str):  # compare_str don't modify t_compare_str
                            if IsOpEqual(head3.op2, 'esp'):
                                late_except_list.append([head3.ea, head3.extend])
                                can_change = True
                                break
                            else:
                                target_reg = head3.op2
                                late_except_list.append([head3.ea, head3.extend])
                        elif target_reg and IsOpEqual(head3.op1, target_reg):
                            if IsOpEqual(head3.op2, 'esp'):
                                can_change = True
                                break
                            else:
                                break
                    elif head3.mnem == 'movzx':
                        if IsOpEqual(head3.op1, t_compare_str):
                            break
                        elif target_reg and IsOpEqual(head3.op1, target_reg):
                            break
                    elif IsCalcMnem(head3.mnem):
                        if target_reg and IsOpEqual(head3.op1, target_reg):
                            if IsNumber(head3.op2) or head3.op2 == False:
                                if head3.mnem == 'add':
                                    stack_change_value += hex2int(head3.op2)
                                elif head3.mnem == 'sub':
                                    stack_change_value -= hex2int(head3.op2)
                                elif head3.mnem == 'inc':
                                    stack_change_value += 1
                                elif head3.mnem == 'dec':
                                    stack_change_value -= 1
                                else:
                                    break
                            else:
                                break
                        elif not target_reg and IsOpEqual(cur.op1, 'esp') and IsOpEqual(head3.op1, t_compare_str):
                            if IsNumber(head3.op2) or head3.op2 == False:
                                late_except_list.append([head3.ea, head3.extend])
                                if head3.mnem == 'add':
                                    stack_change_value += hex2int(head3.op2)
                                elif head3.mnem == 'sub':
                                    stack_change_value -= hex2int(head3.op2)
                                elif head3.mnem == 'inc':
                                    stack_change_value += 1
                                elif head3.mnem == 'dec':
                                    stack_change_value -= 1
                                else:
                                    is_err = True
                                    break
                            else:
                                is_err = True
                                break
                        elif IsOpEqual(head3.op1, t_compare_str):
                            can_change = False
                            break
                    elif head3.mnem == 'xchg':
                        if target_reg and (IsOpEqual(head3.op1, target_reg) or IsOpEqual(head3.op2, target_reg)):
                            break
                    elif head3.mnem == 'pop':
                        t_push_count += 1
                        if target_reg and IsOpEqual(head3.op1, target_reg):
                            break
                if not target_reg and IsOpEqual(cur.op1, 'esp') and not is_err:
                    can_change = True
                if can_change:
                    is_cur_remove = False
                    if target_reg:
                        stack_change_value -= 4
                    if stack_change_value > 0:
                        curHeadRemove()
                        is_cur_remove = True
                        for info in late_except_list:
                            head = GetHead(info)
                            addHeadinExceptList(head)
                            delHeadinTraceList(head.ea, head.extend)
                        addHeadinModifyList(head2.ea, head2.extend, 'add', 'esp', int2hex(stack_change_value))
                    elif stack_change_value == -4:
                        addHeadinExceptList(head2)
                        delHeadinTraceList(head2.ea, head2.extend)
                    elif stack_change_value < -4:
                        stack_change_value = ~stack_change_value + 1
                        stack_change_value -= 4
                        addHeadinModifyList(head2.ea, head2.extend, 'sub', 'esp', int2hex(stack_change_value))
                    elif stack_change_value == 0:
                        curHeadRemove()
                        is_cur_remove = True
                        for info in late_except_list:
                            head = GetHead(info)
                            addHeadinExceptList(head)
                            delHeadinTraceList(head.ea, head.extend)
                        addHeadinExceptList(head2)
                        delHeadinTraceList(head2.ea, head2.extend)
                    if is_cur_remove:
                        t_push_count = 0
                        traceTemp = list(traceList)
                        traceTemp.pop()
                        while len(traceTemp) > 1:
                            head3 = GetHead(traceTemp.pop())
                            if head3.extend:
                                print_log('\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                            else:
                                print_log('\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                            if IsPushMnem(head3.mnem):
                                t_push_count -= 1
                            t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                            if head3.mnem == 'mov':
                                if IsOpEqual(head3.op1, t_compare_str):
                                    addHeadinExceptList(head3)
                            elif head3.mnem == 'movzx':
                                if IsOpEqual(head3.op1, t_compare_str):
                                    addHeadinExceptList(head3)
                            elif IsCalcMnem(head3.mnem):
                                if IsOpEqual(head3.op1, t_compare_str):
                                    addHeadinExceptList(head3)
                            elif head3.mnem == 'pop':
                                t_push_count += 1
                isContinue = False
            elif is_cur_op1_known_value:
                if StrFind(cur.op1, '[esp'):
                    t_num = GetEspNumber(cur.op1)
                    t_num += 4
                    op2 = '[esp+%s]' % int2hex(t_num)
                    addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, op2)
                    check2 = False
                elif IsOpEqual(cur.op1, 'esp'):
                    reserve_esp_modify_list.append([head2.ea, head2.extend, reserve_esp_count])
                    check2 = True
                    print_log('\t\t\treserve esp modify list append(esp_count : %d)\n' % reserve_esp_count)
                elif IsOpEqual(head2.op1, cur.op1):
                    t_push_count = push_count
                    isContinue2 = True
                    if not is_cur_target_reg_changed:
                        addHeadinExceptList(head2)
                        delHeadinTraceList(head2.ea, head2.extend)
                        check1 = False
                        check2 = False
                        isContinue2 = False
                    head3 = head2
                    while isContinue2:
                        head3 = NextHead(head3)
                        if not head3:
                            break
                        if not IsHeadinExceptList(head3):
                            if head3.extend:
                                print_log('\t\tpush mov second loop check(0x%x(%d)) : %s\n' % (
                                head3.ea, head3.extend, GetDisasm(head3)))
                            else:
                                print_log('\t\tpush mov second loop check(0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                            t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                            print_log('\t\t\tcompare_str : %s\n' % t_compare_str)
                            if head3.mnem == 'mov':
                                if IsOpEqual(head3.op2, cur.op1):
                                    isContinue2 = False
                                elif IsOpEqual(head3.op1, t_compare_str):
                                    isContinue2 = False
                            elif head3.mnem == 'movzx':
                                if IsOpEqual(head3.op2, cur.op1):
                                    isContinue2 = False
                                elif IsOpEqual(head3.op1, t_compare_str):
                                    isContinue2 = False
                            elif IsCalcMnem(head3.mnem):
                                if IsOpEqual(head3.op2, cur.op1):
                                    isContinue2 = False
                                elif IsOpEqual(head3.op1, t_compare_str):
                                    isContinue2 = False
                                elif head3.mnem == 'add':
                                    if IsOpEqual(head3.op1,
                                                 'esp') and head3.op2 == '4':  # push edi / mov edi,[esp] / add esp, 4
                                        addHeadinExceptList(head2)
                                        delHeadinTraceList(head2.ea, head2.extend)
                                        isContinue2 = False
                                        addHeadinModifyList(head3.ea, head3.extend, 'pop', cur.op1, False)
                                        check1 = False
                                elif head3.mnem == 'sub':
                                    if IsOpEqual(head3.op1, 'esp'):
                                        isContinue2 = False
                            elif head3.mnem == 'xchg':
                                isContinue2 = False
                            elif IsPushMnem(head3.mnem):
                                isContinue2 = False
                            elif head3.mnem == 'pop':
                                isContinue2 = False
                else:
                    if not IsUsedOpAsOp1(last_target_op_change, cur.op1) and cur.op1:
                        op2 = cur.op1
                        addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, op2)
                        check2 = False
        if check1:
            if StrFind(head2.op2, cur.op1) or StrFind(head2.op2, 'esp'):
                can_push_pop_remove = False
        if check2:
            is_cur_stack_used = True
    elif IsOpEqual(head2.op1, cur.op1): # ex) push esi / mov esi, op2
        isContinue2 = True
        stack_change_except_list = [head2]
        stack_change_exchange = False
        is_op1_stack_pointer = False
        traceList2 = list(traceList)
        is_head2_op1_known_value = True
        is_head2_op1_real_value = False
        is_head2_op2_changed = False
        t_push_count = push_count
        t_push_count2 = 0
        t_push_count3 = 0
        is_ensure_merge = True
        new_reg_value = head2.op2
        org_push_reg_mnem = head2.op1

        is_op1_used2 = False
        if StrFind(head2.op1, '[esp'):
            is_op1_stack_pointer = True
            t_push_count3 = GetEspNumber(head2.op1) / 4
        if IsNumber(head2.op2):
            is_head2_op1_real_value = True
        if IsOpEqual(head2.op1, head2.op2):
            addHeadinExceptList(head2)
            delHeadinTraceList(head2.ea, head2.extend)
            isContinue2 = False
        elif IsOpEqual(head2.op1, 'esp'):
            isContinue = False
            isContinue2 = False
        else:
            if not IsNumber(head2.op2) and not is_cur_stack_changed:
                cur_target_reg_point_reg = head2.op2
                is_cur_target_reg_point_reg_changed = False
            is_cur_target_reg_changed = True
        head2_op2_reference_reg = GetReferenceReg(head2.op2)
        if head2_op2_reference_reg and not IsNumber(head2_op2_reference_reg):
            is_head2_op1_known_value = False
        head3 = head2
        while isContinue2:
            head3 = NextHead(head3)
            if not head3:
                isContinue2 = False
                break
            traceList2.append([head3.ea, head3.extend])
            if not IsHeadinExceptList(head3):
                if head3.extend:
                    print_log('\t\tpush mov second loop check(0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                else:
                    print_log('\t\tpush mov second loop check(0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                if IsJump(head3.mnem):
                    break
                if IsPushMnem(head3.mnem):
                    is_ensure_merge = False
                    can_stack_change_check = False
                    if is_op1_stack_pointer:
                        t_compare_str = t_push_count3 > 0 and '[esp+%s' % int2hex(t_push_count3 * 4) + ']' or '[esp]'
                        print_log('\t\t\tcompare_str : %s\n' % t_compare_str)
                        if IsOpEqual(head3.op1, t_compare_str):
                            is_op1_used2 = True
                    else:
                        if IsOpEqual(head3.op1, head2.op1):
                            if IsNumber(head2.op2) and is_head2_op1_real_value:
                                addHeadinModifyList(head3.ea, head3.extend, head3.mnem, new_reg_value, False)
                            else:
                                is_op1_used2 = True
                        elif IsOpEqualReferenceReg(head3.op1, head2.op1):
                            if IsOpInReferenceRegIncludeSameReg(head3.op1, head2.op1):
                                if IsNumber(head2.op2) and is_head2_op1_real_value:
                                    if IsOpWord(head3.op1):
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem,
                                                            'word ptr [%s]' % new_reg_value, False)
                                    elif IsOpByte(head3.op1):
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem,
                                                            'byte ptr [%s]' % new_reg_value, False)
                                    else:
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem,
                                                            'dword ptr [%s]' % new_reg_value, False)
                                else:
                                    is_op1_used2 = True
                            else:
                                is_op1_used2 = True
                        elif IsLowBitSameRegister(head3.op1, head2.op1):
                            is_op1_used2 = True
                    t_push_count += 1
                    t_push_count2 += 1
                    t_push_count3 += 1
                elif head3.mnem == 'pop':
                    if IsOpEqual(head3.op1, '[esp]') and head2.op2 == '[esp+4]':
                        curHeadRemove()
                        addHeadinExceptList(head2)
                        delHeadinTraceList(head2.ea,head2.extend)
                        delHeadinTraceList2(head2.ea, head2.extend)
                        addHeadinModifyList(head3.ea, head3.extend, 'xchg', head2.op1, '[esp]')
                        isContinue2 = False
                        isContinue = False
                        traceTemp = list(traceList2)
                        traceTemp.pop()
                        while len(traceTemp) > 1:
                            head3 = GetHead(traceTemp.pop())
                            op1 = head3.op1
                            op2 = head3.op2
                            if head3.extend:
                                print_log('\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                            else:
                                print_log('\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                            if head3.op1 and StrFind(head3.op1, '[esp'):
                                t_num = GetEspNumber(head3.op1)
                                t_num -= 4
                                if t_num > 0:
                                    op1 = '[esp+%s]' % int2hex(t_num)
                                elif t_num == 0:
                                    op1 = '[esp]'
                                elif t_num < 0:
                                    op1 = '[esp%s]' % int2hex(t_num)
                            if head3.op2 and StrFind(head3.op2, '[esp'):
                                t_num = GetEspNumber(head3.op2)
                                t_num -= 4
                                if t_num > 0:
                                    op2 = '[esp+%s]' % int2hex(t_num)
                                elif t_num == 0:
                                    op2 = '[esp]'
                                elif t_num < 0:
                                    op2 = '[esp%s]' % int2hex(t_num)
                            addHeadinModifyList(head3.ea, head3.extend, head3.mnem, op1, op2)
                    if stack_change_exchange:
                        isContinue2 = False
                    else:
                        if IsOpEqual(head3.op1, new_reg_value):
                            isContinue2 = False
                            break
                        can_stack_change_check = False
                        if t_push_count == 0:
                            isContinue2 = False
                        elif t_push_count == 1:
                            is_ensure_merge = True
                        t_push_count -= 1
                        t_push_count2 -= 1
                        t_push_count3 -= 1
                    if is_op1_stack_pointer:
                        if t_push_count3 < 0:
                            break
                        t_compare_str = t_push_count3 > 0 and '[esp+%s' % int2hex(t_push_count3 * 4) + ']' or '[esp]'
                        print_log('\t\t\tcompare_str : %s\n' % t_compare_str)
                        if IsOpEqual(head3.op1, t_compare_str):
                            break
                    else:
                        if IsOpEqual(head3.op1, head2.op1):
                            isContinue2 = False
                        elif IsOpInReferenceReg(head3.op1, head2.op1):
                            if IsOpInReferenceRegIncludeSameReg(head3.op1, head2.op1):
                                if is_head2_op1_real_value:
                                    if IsOpWord(head3.op1):
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem,
                                                            'word ptr [%s]' % new_reg_value,
                                                            False)
                                    elif IsOpByte(head3.op1):
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem,
                                                            'byte ptr [%s]' % new_reg_value,
                                                            False)
                                    else:
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem,
                                                            'dword ptr [%s]' % new_reg_value, False)
                                else:
                                    is_op1_used2 = True
                            else:
                                is_op1_used2 = True
                        elif IsLowBitSameRegister(head3.op1, head2.op1):
                            is_op1_used2 = True
                            is_head2_op1_known_value = False
                            is_head2_op1_real_value = False
                            isContinue2 = False
                elif head3.mnem == 'mov':
                    if IsOpEqual(head3.op1, head2.op2):
                        is_head2_op2_changed = True
                    if is_op1_stack_pointer:
                        t_compare_str2 = t_push_count3 > 0 and '[esp+%s' % int2hex(t_push_count3 * 4) + ']' or '[esp]'
                        print_log('\t\t\tcompare_str : %s\n' % t_compare_str2)
                        if IsOpEqual(head3.op1, t_compare_str2):
                            if not is_op1_used2:
                                addHeadinExceptList(head2)
                                delHeadinTraceList(head2.ea, head2.extend)
                                is_cur_target_reg_changed = False
                            isContinue2 = False
                        elif IsOpEqual(head3.op2, t_compare_str2):
                            is_op1_used2 = True
                        elif IsOpEqual(head3.op1, 'esp'):
                            isContinue2 = False
                    else:
                        t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                        print_log('\t\t\tcompare_str : %s\n' % t_compare_str)
                        if IsOpEqual(head3.op1, t_compare_str):
                            isContinue2 = False
                        elif head3.op1 == 'esp' and IsOpEqual(head3.op2, '[esp]') and can_stack_change_check:
                            isContinue2 = False
                        elif IsOpEqual(head3.op1, head2.op1):
                            if IsOpInReferenceReg(head3.op2, head2.op1):
                                change = False
                                if IsOpEqualReferenceReg(head3.op2, head2.op1):
                                    if is_head2_op1_real_value:
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1,
                                                            '[%s]' % new_reg_value)
                                        change = True
                                if not change:
                                    is_op1_used2 = True
                            if not is_op1_used2:
                                addHeadinExceptList(head2)
                                delHeadinTraceList(head2.ea, head2.extend)
                                is_cur_target_reg_changed = False
                            isContinue2 = False
                        elif IsLowBitSameRegister(head3.op1, head2.op1):
                            if not is_op1_used2:
                                if IsNumber(head3.op2) and is_head2_op1_real_value:
                                    if IsWordRegister(head3.op1):
                                        high_word = GetHighWord(new_reg_value)
                                        low_word = GetLowWord(head3.op2)
                                        addHeadinExceptList(head2)
                                        delHeadinTraceList(head2.ea, head2.extend)
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head2.op1,
                                                            int2hex(high_word + low_word))
                                        is_cur_target_reg_changed = False
                            isContinue2 = False
                        elif IsOpEqual(head3.op2, head2.op1):
                            if is_head2_op1_real_value:
                                addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1, new_reg_value)
                            elif not IsNumber(head2.op2) and is_head2_op1_known_value and not is_head2_op2_changed and not StrFind(head2.op2, '[esp'):
                                addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1, head2.op2)
                            else:
                                is_op1_used2 = True
                        elif StrFind(head3.op1, head2.op1):
                            is_op1_used2 = True
                        elif StrFind(head3.op2, head2.op1):
                            is_op1_used2 = True
                elif head3.mnem == 'movzx':
                    if IsOpEqual(head3.op1, head2.op2):
                        break
                    if is_op1_stack_pointer:
                        t_compare_str2 = t_push_count3 > 0 and '[esp+%s' % int2hex(t_push_count3 * 4) + ']' or '[esp]'
                        print_log('\t\t\tcompare_str : %s\n' % t_compare_str2)
                        if IsOpEqual(head3.op1, t_compare_str2):
                            if not is_op1_used2:
                                addHeadinExceptList(head2)
                                delHeadinTraceList(head2.ea, head2.extend)
                                is_cur_target_reg_changed = False
                            isContinue2 = False
                        elif IsOpEqual(head3.op2, t_compare_str2):
                            is_op1_used2 = True
                        elif IsOpEqual(head3.op1, 'esp'):
                            isContinue2 = False
                    else:
                        t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                        print_log('\t\t\tcompare_str : %s\n' % t_compare_str)
                        if IsOpEqual(head3.op1, t_compare_str):
                            isContinue2 = False
                        elif IsOpEqual(head3.op1, head2.op1):
                            if IsOpInReferenceReg(head3.op2, head2.op1):
                                break
                            if not is_op1_used2:
                                addHeadinExceptList(head2)
                                delHeadinTraceList(head2.ea, head2.extend)
                                is_cur_target_reg_changed = False
                            isContinue2 = False
                        elif IsLowBitSameRegister(head3.op1, head2.op1):
                            isContinue2 = False
                        elif IsOpEqual(head3.op2, head2.op1):
                            if is_head2_op1_real_value:
                                addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1, new_reg_value)
                            elif not IsNumber(head2.op2) and is_head2_op1_known_value and not is_head2_op2_changed:
                                addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1, head2.op2)
                            else:
                                is_op1_used2 = True
                        elif StrFind(head3.op1, head2.op1):
                            is_op1_used2 = True
                        elif StrFind(head3.op2, head2.op1):
                            is_op1_used2 = True
                elif IsCalcMnem(head3.mnem):
                    if IsOpEqual(head3.op1, head2.op2):
                        is_head2_op2_changed = True
                    if is_op1_stack_pointer:
                        t_compare_str2 = t_push_count3 > 0 and '[esp+%s' % int2hex(t_push_count3 * 4) + ']' or '[esp]'
                        print_log('\t\t\tcompare_str : %s\n' % t_compare_str2)
                        if IsOpEqual(head3.op1, t_compare_str2):
                            isContinue2 = False
                        elif IsOpEqual(head3.op2, t_compare_str2):
                            is_op1_used2 = True
                        if head3.mnem == 'add' and IsOpEqual(head3.op1, 'esp'):
                            t_push_count3 -= 1
                        elif head3.mnem == 'sub' and IsOpEqual(head3.op1, 'esp'):
                            t_push_count3 += 1
                    else:
                        if not IsNumber(cur.op1) and IsOpEqual(head3.op2, cur.op1):
                            if is_head2_op1_known_value and not is_head2_op2_changed:  # ex) push edi / mov edi,esp / add edi,4 / xor [esp],edi -> xor [esp],esp(x)
                                if StrFind(head2.op2, '[esp') and not t_push_count == push_count:
                                    isContinue2 = False
                                else:
                                    if IsOpInReferenceReg(new_reg_value, head2.op1):
                                        is_op1_used2 = True
                                    else:
                                        addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1,
                                                            new_reg_value)
                            else:
                                is_op1_used2 = True
                        elif IsLowBitSameRegister(head3.op2, cur.op1):
                            if is_head2_op1_real_value:  # ex) push edi / mov edi,esp / add edi,4 / xor [esp],edi -> xor [esp],esp(x)
                                if IsWordRegister(head3.op2):
                                    t_val = int2hex(hex2int(new_reg_value) & 0xFFFF)
                                    addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1, t_val)
                                elif IsLowHighRegister(head3.op2):
                                    t_val = int2hex((hex2int(new_reg_value) & 0xFF00) >> 8)
                                    addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1, t_val)
                                elif IsLowLowRegister(head3.op2):
                                    t_val = int2hex(hex2int(new_reg_value) & 0xFF)
                                    addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1, t_val)
                            else:
                                is_op1_used2 = True
                        elif not IsOpEqual(head3.op2, cur.op1) and StrFind(head3.op2, cur.op1):
                            is_op1_used2 = True
                        if not IsOpEqual(head3.op1, cur.op1) and StrFind(head3.op1, cur.op1):
                            is_op1_used2 = True
                        elif IsOpEqual(head3.op1, head2.op1) and IsNumber(head2.op2) and (IsNumber(
                                head3.op2) or head3.op2 is False):  # ex) push edx / mov edx, 3204 / sub edx, 394
                            if not is_op1_used2 and is_head2_op1_real_value:
                                new_reg_value = int2hex(calc(head3.mnem, new_reg_value, head3.op2))
                                addHeadinExceptList(head3)
                                delHeadinTraceList(head3.ea, head3.extend)
                                delHeadinTraceList2(head3.ea, head3.extend)
                                addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, new_reg_value)
                        elif IsOpEqual(head3.op1, head2.op1) and IsNumber(head2.op2) and head3.op2 and not IsNumber(
                                head3.op2):
                            if not is_op1_used2 and is_head2_op1_real_value:
                                new_value = False
                                find_reg = head3.op2
                                traceTemp = list(traceList2)
                                traceTemp.pop()
                                print_log('\t\t\ttraceTempSize : %d\n' % (len(traceTemp)))
                                while len(traceTemp) > 1:
                                    head = GetHead(traceTemp.pop())
                                    if head.extend:
                                        print_log(
                                            '\t\t\ttrace  (0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
                                    else:
                                        print_log('\t\t\ttrace  0x%x : %s\n' % (head.ea, GetDisasm(head)))
                                    if head.mnem == 'mov':
                                        if IsOpEqual(head.op1, find_reg):
                                            if IsNumber(head.op2):
                                                new_value = int2hex(unsigned32(hex2int(head.op2)))
                                                addHeadinModifyList(head3.ea, head3.extend, head3.mnem, head3.op1,
                                                                    new_value)
                                                break
                                            else:
                                                find_reg = head.op2
                                    elif head.mnem == 'movzx':
                                        if IsOpEqual(head.op1, find_reg):
                                            break
                                    elif head.mnem == 'pop':
                                        if head.op1 == find_reg:
                                            break
                                    elif head.mnem == 'xchg':
                                        if head.op1 == find_reg or head.op2 == find_reg:
                                            break
                                    elif IsCalcMnem(head.mnem):
                                        if IsOpEqual(head.op1, find_reg):
                                            break
                                if new_value:
                                    head3.op2 = new_value
                                    new_reg_value = int2hex(calc(head3.mnem, new_reg_value, head3.op2))
                                    addHeadinExceptList(head3)
                                    delHeadinTraceList2(head3.ea, head3.extend)
                                    addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, new_reg_value)
                                else:
                                    is_head2_op1_known_value = False
                                    is_head2_op1_real_value = False
                            else:
                                is_head2_op1_known_value = False
                                is_head2_op1_real_value = False
                        elif head3.op1 == 'esp':
                            isContinue2 = False
                        if IsOpEqual(head3.op1, head2.op1) and not IsNumber(head2.op2):
                            is_head2_op1_known_value = False  # push ecx / mov ecx,ebx / xor ecx,329034 / add edx,ecx -> add edx, ebx (x)
                            is_head2_op1_real_value = False
                elif head3.mnem == 'xchg':
                    if is_op1_stack_pointer:
                        t_compare_str = t_push_count3 > 0 and '[esp+%s' % int2hex(t_push_count3 * 4) + ']' or '[esp]'
                        print_log('\t\t\tcompare_str : %s\n' % t_compare_str)
                        if IsOpEqual(head3.op1, t_compare_str) or IsOpEqual(head3.op2, t_compare_str):
                            break
                    else:
                        if IsOpEqual(head3.op1, head2.op2) or IsOpEqual(head3.op2, head2.op2):
                            is_head2_op2_changed = True
                        if IsOpEqual(head3.op1, org_push_reg_mnem) and IsOpEqual(head3.op2,
                                                                                 '[esp]') and can_stack_change_check and head2.op2 == 'esp':
                            is_head2_op1_known_value = False
                            is_head2_op1_real_value = False
                            print_log('\t\t\tstack change xchg on\n')
                            stack_change_exchange = True
                        elif IsOpEqual(head3.op1, org_push_reg_mnem) or IsOpEqual(head3.op2, org_push_reg_mnem):
                            if IsNumber(head2.op2) and is_head2_op1_real_value:
                                t_compare_str = t_push_count > 0 and '[esp+%s' % int2hex(
                                    t_push_count * 4) + ']' or '[esp]'
                                if IsOpEqual(head3.op1, org_push_reg_mnem):
                                    if IsOpEqual(head3.op2, t_compare_str) and is_head2_op1_known_value:
                                        addHeadinModifyList(head3.ea, head3.extend, 'mov', head2.op1, '[esp]')
                                    else:
                                        addHeadinModifyList(head3.ea, head3.extend, 'mov', head2.op1, head3.op2)
                                    addExtendHeadinHead(head3.ea, 'mov', head3.op2, new_reg_value)
                                else:
                                    if IsOpEqual(head3.op2, t_compare_str) and is_head2_op1_known_value:
                                        addHeadinModifyList(head3.ea, head3.extend, 'mov', head2.op1, '[esp]')
                                    else:
                                        addHeadinModifyList(head3.ea, head3.extend, 'mov', head2.op1, head3.op1)
                                    addExtendHeadinHead(head3.ea, 'mov', head3.op1, new_reg_value)
                            else:
                                isExchangeEncounter = True
                            isContinue2 = False
                            break
    elif StrFind(cur.op1, head2.op1): # push dword ptr [ebp+ebx+0] / mov ebx, edx
        is_cur_target_reg_changed = True
    elif IsOpEqual(head2.op1, cur_target_reg_point_reg):
        is_cur_target_reg_point_reg_changed = True
    elif IsOpEqual(head2.op1, 'esp'):
        isContinue = False
    if isContinue and IsOpEqual(head2.op2, 'esp'):
        if not IsHeadinExceptList(head2):
            esp_size_change_late_extend_list.append(head2)
def push_movzx_deob():
    global cur, compare_str, isContinue, is_cur_target_reg_changed, is_cur_target_reg_point_reg_changed
    compare_str = push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]'
    print_log('\t\tmovzx compare_str and op1, op2 : %s\n' % compare_str)
    if IsOpEqual(head2.op1, compare_str):
        isContinue = False
    elif IsOpEqual(head2.op1, cur.op1) or StrFind(cur.op1, head2.op1):
        is_cur_target_reg_changed = True
    elif IsOpEqual(head2.op1, cur_target_reg_point_reg):
        is_cur_target_reg_point_reg_changed = True
def push_calc_deob():
    global cur, except_list
    global compare_str, exchangeTarget, push_count, head2, modifyList, is_op1_used, once_stack_change_register_encounter
    global isContinue, traceList, traceTemp, last_target_op_change, push_mov_late_except_list, isExchangeEncounter
    global reserve_esp_modify_list, push_pop_late_modify_list, is_cur_op1_known_value, is_cur_target_reg_changed
    global cur_stack_calc_list, cur_target_reg, is_cur_target_reg_known_value, is_cur_stack_changed
    global is_cur_target_reg_point_reg_changed, is_cur_stack_used
    if IsOpEqual(head2.op2, cur.op1):
        is_op1_used=True
    compare_str = push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]'
    print_log('\t\tcalc compare_str and op1, op2 : %s , %s, %s\n' % (compare_str, cur.op1, head2.op2))
    if IsOpEqual(head2.op1, cur.op1) or StrFind(cur.op1, head2.op1):
        is_cur_target_reg_changed = True
    elif IsOpEqual(head2.op1, cur_target_reg_point_reg):
        is_cur_target_reg_point_reg_changed = True
    if head2.op1 == 'esp' and IsNumber(head2.op2):
        count = hex2int(head2.op2) / 4
        if head2.mnem == 'add':
            once_stack_change_register_encounter = True
            push_count -= count
        elif head2.mnem == 'sub':
            once_stack_change_register_encounter = True
            push_count += count
        if push_count == -1 and head2.mnem == 'add':
            if not isExchangeEncounter:
                can_change = True
                is_cur_target_reg_changed2 = False
                target_reg = cur.op1
                is_cur_target_stack_pointer = False
                t_push_count2 = 0
                compare_str2 = False
                if StrFind(target_reg, '[esp'):
                    is_cur_target_stack_pointer = True
                    t_push_count2 = GetEspNumber(target_reg) / 4 + 1
                t_push_count = 0
                cur_value_calc_list = []
                late_modify_list = []
                late_except_list = []
                i = 1
                traceTemp = list(traceList)
                traceTemp.pop()
                while i < len(traceTemp):
                    head3 = GetHead(traceTemp[i])
                    if head3.extend:
                        print_log('\t\tcan change check trace  (0x%x(%d)): %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                    else:
                        print_log('\t\tcan change check trace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                    compare_str = t_push_count > 0 and '[esp+%s' % int2hex(t_push_count * 4) + ']' or '[esp]'
                    if IsPushMnem(head3.mnem):
                        if IsOpEqual(head3.op1, compare_str):
                            if not is_cur_target_reg_changed2 and len(cur_value_calc_list) == 0:
                                late_modify_list.append([head3.ea, head3.extend, head3.mnem, cur.op1, False, []])
                            else:
                                can_change = False
                                break
                        t_push_count += 1
                        t_push_count2 += 1
                    elif head3.mnem == 'pop':
                        t_push_count -= 1
                        t_push_count2 -= 1
                        if is_cur_target_stack_pointer:
                            compare_str2 = t_push_count2 > 0 and '[esp+%s' % int2hex(t_push_count2 * 4) + ']' or '[esp]'
                        if not is_cur_target_reg_changed2:
                            if not is_cur_target_stack_pointer and IsOpEqual(head3.op1, target_reg):
                                is_cur_target_reg_changed2 = True
                            elif is_cur_target_stack_pointer and IsOpEqual(head3.op1, compare_str2):
                                is_cur_target_reg_changed2 = True
                    elif IsCalcMnem(head3.mnem):
                        if is_cur_target_stack_pointer:
                            compare_str2 = t_push_count2 > 0 and '[esp+%s' % int2hex(t_push_count2 * 4) + ']' or '[esp]'
                        if head3.op1 == 'esp' and not IsNumber(head3.op2):
                            can_change = False
                            break
                        elif head3.mnem == 'sub' and head3.op1 == 'esp' and IsNumber(head3.op2):
                            stack_count = hex2int(head3.op2) / 4
                            t_push_count += stack_count
                            t_push_count2 += stack_count
                        elif head3.mnem == 'add' and head3.op1 == 'esp' and IsNumber(head3.op2):
                            stack_count = hex2int(head3.op2) / 4
                            t_push_count -= stack_count
                            t_push_count2 -= stack_count
                        if IsOpEqual(head3.op1, compare_str):
                            cur_value_calc_list.append([head3.mnem, head3.op2])
                            late_except_list.append([head3.ea, head3.extend])
                        elif IsOpEqual(head3.op2, compare_str):
                            if not is_cur_target_reg_changed2 and len(cur_value_calc_list) == 0:
                                late_modify_list.append([head3.ea, head3.extend, head3.mnem, head3.op1, cur.op1, []])
                            else:
                                can_change = False
                                break
                        if not is_cur_target_reg_changed2:
                            if not is_cur_target_stack_pointer and IsOpEqual(head3.op1, target_reg):
                                is_cur_target_reg_changed2 = True
                            elif is_cur_target_stack_pointer and IsOpEqual(head3.op1, compare_str2):
                                is_cur_target_reg_changed2 = True
                    elif head3.mnem == 'mov':
                        if is_cur_target_stack_pointer:
                            compare_str2 = t_push_count2 > 0 and '[esp+%s' % int2hex(t_push_count2 * 4) + ']' or '[esp]'
                        if IsOpEqual(head3.op2, compare_str):
                            if not is_cur_target_reg_changed2:
                                insert = [head3.ea, head3.extend, head3.mnem, head3.op1, cur.op1, []]
                                for info in cur_value_calc_list:
                                    insert[5].append([info[0], info[1]])
                                late_modify_list.append(insert)
                            else:
                                can_change = False
                                break
                        elif IsOpEqual(head3.op1, compare_str):
                            can_change = False
                            break
                        if not is_cur_target_reg_changed2:
                            if not is_cur_target_stack_pointer and IsOpEqual(head3.op1, target_reg):
                                is_cur_target_reg_changed2 = True
                            elif is_cur_target_stack_pointer and IsOpEqual(head3.op1, compare_str2):
                                is_cur_target_reg_changed2 = True
                    elif head3.mnem == 'movzx':
                        if is_cur_target_stack_pointer:
                            compare_str2 = t_push_count2 > 0 and '[esp+%s' % int2hex(t_push_count2 * 4) + ']' or '[esp]'
                        if IsOpEqual(head3.op2, compare_str):
                            if not is_cur_target_reg_changed2:
                                insert = [head3.ea, head3.extend, head3.mnem, head3.op1, cur.op1, []]
                                for info in cur_value_calc_list:
                                    insert[5].append([info[0], info[1]])
                                late_modify_list.append(insert)
                            else:
                                can_change = False
                                break
                        if not is_cur_target_reg_changed2:
                            if not is_cur_target_stack_pointer and IsOpEqual(head3.op1, target_reg):
                                is_cur_target_reg_changed2 = True
                            elif is_cur_target_stack_pointer and IsOpEqual(head3.op1, compare_str2):
                                is_cur_target_reg_changed2 = True
                    elif head3.mnem == 'xchg':
                        if is_cur_target_stack_pointer:
                            compare_str2 = t_push_count2 > 0 and '[esp+%s' % int2hex(t_push_count2 * 4) + ']' or '[esp]'
                        if IsOpEqual(head3.op2, compare_str):
                            can_change = False
                            break
                        if not is_cur_target_reg_changed2:
                            if not is_cur_target_stack_pointer and (IsOpEqual(head3.op1, target_reg) or IsOpEqual(head3.op2, target_reg)):
                                is_cur_target_reg_changed2 = True
                            elif is_cur_target_stack_pointer and (IsOpEqual(head3.op1, compare_str2) or IsOpEqual(head3.op2, compare_str2)):
                                is_cur_target_reg_changed2 = True
                    i += 1
                if can_change:
                    curHeadRemove()
                    for info in late_except_list:
                        head = GetHead(info)
                        addHeadinExceptList(head)
                        delHeadinTraceList(head.ea, head.extend)
                    for info in reserve_esp_modify_list:
                        head = GetHead([info[0], info[1]])
                        addHeadinModifyList(head.ea, head.extend, head.mnem, head.op1, 'esp')
                        if info[2] > 0:
                            addExtendHeadinHead(head2.ea, 'sub', head2.op1, int2hex(info[2]*4))
                        elif info[2] < 0:
                            addExtendHeadinHead(head2.ea, 'add', head2.op1, int2hex(info[2] * 4))
                        reserve_esp_modify_list.remove(info)
                    for info in late_modify_list:
                        addHeadinModifyList(info[0], info[1], info[2], info[3], info[4])
                        for calc_info in info[5]:
                            addExtendHeadinHead(info[0], calc_info[0], info[3], calc_info[1])
                    late_modify_list = []
                    t_reverse_push_count=0
                    traceTemp = list(traceList)
                    traceTemp.pop()
                    while len(traceTemp) > 1:
                        head3 = GetHead(traceTemp.pop())
                        op1 = head3.op1
                        op2 = head3.op2
                        change = False
                        if head3.extend:
                            print_log('\t\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                        else:
                            print_log('\t\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                        if IsPushMnem(head3.mnem):
                            t_reverse_push_count -= 1
                        if head3.op1 and StrFind(head3.op1, '[esp'):
                            t_num = GetEspNumber(head3.op1)
                            if (t_num / 4) > t_reverse_push_count:
                                t_num -= 4
                                if t_num > 0:
                                    op1 = '[esp+%s]' % int2hex(t_num)
                                elif t_num == 0:
                                    op1 = '[esp]'
                                elif t_num < 0:
                                    op1 = '[esp%s]' % int2hex(t_num)
                                change = True
                        if head3.op2 and StrFind(head3.op2, '[esp'):
                            t_num = GetEspNumber(head3.op2)
                            if (t_num / 4) > t_reverse_push_count:
                                t_num -= 4
                                if t_num > 0:
                                    op2 = '[esp+%s]' % int2hex(t_num)
                                elif t_num == 0:
                                    op2 = '[esp]'
                                elif t_num < 0:
                                    op2 = '[esp%s]' % int2hex(t_num)
                                change = True
                        if change:
                            addHeadinModifyList(head3.ea, head3.extend, head3.mnem, op1, op2)
                        if head3.mnem == 'pop':
                            t_reverse_push_count += 1
                    if head2.op2 == '4':
                        addHeadinExceptList(head2)
                    else:
                        addHeadinModifyList(head2.ea, head2.extend, head2.mnem, head2.op1, int2hex(hex2int(head2.op2) - 4))
                    for head in esp_size_change_late_extend_list:
                        if not IsHeadinExceptList(head):
                            addExtendHeadinHead(head.ea, 'sub', head.op1, '4')
        isContinue = False
    if IsOpEqual(head2.op1, compare_str):
        is_cur_stack_changed = True
        if not is_cur_stack_used and is_cur_target_reg_known_value and IsNeedOp2CalcMnem(head2.mnem) and IsNumber(cur.op1) and IsNumber(head2.op2):
            cur.op1 = int2hex(calc(head2.mnem, cur.op1, head2.op2))
            last_target_op_change = [head2.ea, head2.extend]
            print_log('\t\tcurrent target change : %s %s\n' % (cur.mnem, cur.op1))
            addHeadinExceptList(head2)
            delHeadinTraceList(head2.ea, head2.extend)
        elif not is_cur_stack_used and is_cur_target_reg_known_value and IsSingleCalcMnem(head2.mnem) and IsNumber(cur.op1):
            cur.op1 = int2hex(calc(head2.mnem, cur.op1, False))
            last_target_op_change = [head2.ea, head2.extend]
            print_log('\t\tcurrent target change : %s %s\n' % (cur.mnem, cur.op1))
            addHeadinExceptList(head2)
            delHeadinTraceList(head2.ea, head2.extend)
        else:
            if not IsNumber(cur.op1) and IsNumber(head2.op2) and is_cur_target_reg_known_value:
                cur_stack_calc_list.append([head2.mnem, cur_target_reg, head2.op2])
            elif not IsNumber(cur.op1) and not IsNumber(head2.op2) and is_cur_target_reg_known_value:
                is_cur_target_reg_known_value = False
                cur_stack_calc_list = []
            elif IsNumber(cur.op1) and not IsNumber(head2.op2) and is_cur_target_reg_known_value:
                is_cur_target_reg_known_value = False
                cur_stack_calc_list = []
            push_mov_late_except_list.append(head2)
            push_pop_late_modify_list.append([head2.ea, head2.extend, cur.op1])
            is_cur_op1_known_value = False
    elif IsOpEqual(head2.op2, compare_str):
        is_cur_stack_used = True
def push_xchg_deob():
    global modifyList, cur, except_list
    global isExchanged, compare_str, exchangeTarget, push_count, head2, exchange_ea
    global traceList, last_target_op_change, isExchangeEncounter, is_op1_used, is_cur_target_reg_changed, is_cur_target_reg_known_value
    global cur_target_reg, cur_stack_calc_list, cur_target_reg_point_reg, is_cur_target_reg_point_reg_changed
    if IsOpEqual(cur.op1, head2.op2) or IsOpEqual(cur.op1, head2.op1):
        is_op1_used=True
    compare_str = push_count > 0 and '[esp+%s' % int2hex(push_count * 4) + ']' or '[esp]'
    print_log('\t\txchg compare_str : %s\n' % compare_str)
    if IsOpEqual(head2.op1, compare_str) or IsOpEqual(head2.op2, compare_str):
        if cur_target_reg_point_reg and not is_cur_target_reg_point_reg_changed:
            print_log("\t\thaha111\n")
            can_change = True
            target_reg = False
            target_reg_point_reg = False
            target_reg_point_reg_changed = False
            cur_reg = False
            if IsOpEqual(head2.op1, compare_str):
                cur_reg = head2.op1
                target_reg = head2.op2
            else:
                cur_reg = head2.op2
                target_reg = head2.op1
            late_modify_extend_calc_list = []
            late_modify = ['mov', cur_reg, target_reg]
            traceTemp = list(traceList)
            traceTemp.pop()
            i = 1
            while not i == len(traceTemp):
                head3 = GetHead(traceTemp[i])
                if head3.extend:
                    print_log('\t\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                else:
                    print_log('\t\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                if head3.mnem == 'mov':
                    if IsOpEqual(head3.op1, target_reg):
                        late_modify[2] = head3.op2
                        target_reg_point_reg = head3.op2
                        target_reg_point_reg_changed = False
                        late_modify_extend_calc_list = []
                    elif target_reg_point_reg and IsOpEqual(head3.op1, target_reg_point_reg):
                        target_reg_point_reg_changed = True
                elif head3.mnem == 'movzx':
                    if IsOpEqual(head3.op1, target_reg):
                        break
                    elif target_reg_point_reg and IsOpEqual(head3.op1, target_reg_point_reg):
                        break
                elif head3.mnem == 'pop':
                    if IsOpEqual(head3.op1, head2.op1):
                        can_change = False
                        break
                    elif IsOpEqual(head3.op1, head2.op2):
                        can_change = False
                        break
                    if target_reg_point_reg and IsOpEqual(head3.op1, target_reg_point_reg):
                        target_reg_point_reg_changed = True
                elif IsCalcMnem(head3.mnem):
                    if IsOpEqual(head3.op1, target_reg):
                        if IsNumber(head3.op2):
                            late_modify_extend_calc_list.append([head3.mnem, head3.op2])
                        else:
                            can_change = False
                            break
                    elif target_reg_point_reg and IsOpEqual(head3.op1, target_reg_point_reg):
                        target_reg_point_reg_changed = True
                i += 1
            if can_change and not target_reg_point_reg_changed:
                addHeadinModifyList(head2.ea, head2.extend, 'mov', target_reg, compare_str)
                head2.mnem = 'mov'
                head2.op1 = target_reg
                head2.op2 = compare_str
                for info in cur_stack_calc_list:
                    addExtendHeadinHead(head2.ea, info[0], info[1], info[2])
                addExtendHeadinHead(head2.ea, late_modify[0], late_modify[1], late_modify[2])
                for info in late_modify_extend_calc_list:
                    addExtendHeadinHead(head2.ea, info[0], cur_reg, info[1])
                if not head2.extend:
                    print_log('\tcheck 0x%x\n' % head2.ea)
                else:
                    print_log('\tcheck 0x%x(%d)\n' % (head2.ea, head2.extend))
                push_mov_deob()
        elif not is_cur_target_reg_changed and IsNumber(cur.op1): #pattern 1
            print_log("\t\thaha222\n")
            can_change = True
            target_reg = False
            cur_reg = False
            if IsOpEqual(head2.op1, '[esp]'):
                cur_reg = head2.op1
                target_reg = head2.op2
            else:
                cur_reg = head2.op2
                target_reg = head2.op1
            late_modify = ['mov', cur_reg, target_reg]
            late_modify_extend_calc_list = []
            traceTemp = list(traceList)
            traceTemp.pop()
            while len(traceTemp) > 1:
                head3 = GetHead(traceTemp.pop())
                if head3.extend:
                    print_log('\t\t\ttrace  (0x%x(%d)) : %s\n' % (head3.ea, head3.extend, GetDisasm(head3)))
                else:
                    print_log('\t\t\ttrace  (0x%x) : %s\n' % (head3.ea, GetDisasm(head3)))
                if head3.mnem == 'mov':
                    if IsOpEqual(head3.op1, target_reg):
                        late_modify[2] = head3.op2
                        break
                elif head3.mnem == 'movzx':
                    if IsOpEqual(head3.op1, target_reg):
                        can_change = False
                        break
                elif head3.mnem == 'pop':
                    if IsOpEqual(head3.op1, head2.op1):
                        break
                    elif IsOpEqual(head3.op1, head2.op2):
                        break
                elif IsCalcMnem(head3.mnem):
                    if IsOpEqual(head3.op1, target_reg):
                        if IsNumber(head3.op2):
                            if IsSingleCalcMnem(head3.mnem):
                                late_modify_extend_calc_list.append([head3.mnem, False])
                            else:
                                late_modify_extend_calc_list.append([head3.mnem, head3.op2])
                        else:
                            can_change = False
                            break
            if can_change:
                addHeadinModifyList(head2.ea, head2.extend, late_modify[0], late_modify[1], late_modify[2])
                if not late_modify[2] == target_reg:
                    for info in late_modify_extend_calc_list:
                        addExtendHeadinHead(head2.ea, info[0], cur_reg, info[1])
                addExtendHeadinHead(head2.ea, 'mov', target_reg, cur.op1)

                head2.mnem = late_modify[0]
                head2.op1 = late_modify[1]
                head2.op2 = late_modify[2]
                push_mov_deob()
        else: # pattern 2
            print_log("\t\thaha333\n")
            isExchangeEncounter = True
            isExchanged = True
            in_exchange_range_ea_list = []
            head3 = head2
            isContinue2 = True
            while isContinue2:
                head3 = NextHead(head3)
                if not head3:
                    break
                in_exchange_range_ea_list.append([head3.ea, head3.extend])
                if head3.mnem == 'xchg':
                    if head2.op1 == head3.op2 and head2.op2 == head3.op1:
                        isExchanged = False
                        for head_info in in_exchange_range_ea_list:
                            head = GetHead(head_info)
                            if head.op1 == head2.op1 or head.op1 == head2.op2 or head.op2 == head2.op1 or head.op2 == head2.op2:
                                op1 = False
                                op2 = False
                                if head.op1 == head2.op1:
                                    op1 = head2.op2
                                elif head.op1 == head2.op2:
                                    op1 = head2.op1
                                else:
                                    op1 = head.op1

                                if head.op2 == head2.op1:
                                    op2 = head2.op2
                                elif head.op2 == head2.op2:
                                    op2 = head2.op1
                                else:
                                    op2 = head.op2
                                addHeadinModifyList(head.ea, head.extend, head.mnem, op1, op2)
                        addHeadinExceptList(head2)
                        addHeadinExceptList(head3)
                        delHeadinTraceList(head2.ea, head2.extend)
                        break
                elif IsJump(head3.mnem):
                    break
            last_target_op_change = [head2.ea, head2.extend]
    elif IsOpEqual(head2.op1, cur.op1):
        isExchangeEncounter = True
        is_cur_target_reg_changed = True
    elif IsOpEqual(head2.op2, cur.op1):
        isExchangeEncounter = True
        is_cur_target_reg_changed = True
def IsUsedOpAsOp1(start_ea,op):
    global traceTemp,traceList
    isContinue2 = True
    traceTemp = list(traceList)
    traceTemp.pop()
    i = 0
    if start_ea:
        for info in traceTemp:
            if info[0] > start_ea[0]:
                i = traceTemp.index(info)
                break
            elif info[0] == start_ea[0]:
                if info[1] and not start_ea[0]:
                    i = traceTemp.index(info)
                    break
        if i == 0:
            isContinue2 = False
    else:
        i = 1
    print_log('\t\t\t------IsUsedOpAsOp1 check loop------\n')
    print_log('\t\t\ttraceTempSize : %d\n' % (len(traceTemp)))
    while isContinue2 and i < len(traceTemp):
        head = GetHead(traceTemp[i])
        if head.extend:
            print_log('\t\t\ttrace  (0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
        else:
            print_log('\t\t\ttrace  0x%x : %s\n' % (head.ea, GetDisasm(head)))
        if head.mnem == 'mov':
            if IsOpEqual(op, head.op1):
                return True
        elif head.mnem == 'movzx':
            if IsOpEqual(op, head.op1):
                return True
        elif IsCalcMnem(head.mnem):
            if IsOpEqual(op, head.op1):
                return True
        i += 1
    return False
def calc(mnem, op1, op2):
    a = False
    if isinstance(op1, str):
        a = hex2int(op1)
    else:
        a = op1
    if op2 and IsNumber(op2):
        b = hex2int(op2)
    if mnem == 'add':
        a += b
    elif mnem == 'sub':
        a -= b
    elif mnem == 'xor':
        a ^= b
    elif mnem == 'or':
        a |= b
    elif mnem == 'and':
        a &= b
    elif mnem == 'shr':
        a = a >> b
    elif mnem == 'shl':
        a = a << b
    elif mnem == 'not':
        a = ~a
    elif mnem == 'neg':
        a = ~a+1
    elif mnem == 'dec':
        a -= 1
    elif mnem == 'inc':
        a += 1
    a = unsigned32(a)
    return a
def long_calc(mnem, op1, op2):
    a = hex2int(op1)
    if op2 and IsNumber(op2):
        b = hex2int(op2)
    if mnem == 'add':
        a += b
    elif mnem == 'sub':
        a -= b
    elif mnem == 'xor':
        a ^= b
    elif mnem == 'or':
        a |= b
    elif mnem == 'and':
        a &= b
    elif mnem == 'shr':
        a = a >> b
    elif mnem == 'shl':
        a = a << b
    elif mnem == 'not':
        a = ~a
    elif mnem == 'neg':
        a = ~a + 1
    elif mnem == 'dec':
        a -= 1
    elif mnem == 'inc':
        a += 1
    return a
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
    return re.split(r'([+-])+',op)
def GetRegValue(op):
    global new_ins_list, saved_offset_list
    reg_list = []
    calc_list = []
    result = 0
    success = True
    t = GetRegInfo(op)
    i = 0
    for a in t:
        if i % 2 == 0:
            reg_list.append(a)
        else:
            calc_list.append(a)
        i += 1
    i = 0
    while i < len(reg_list):
        t_continue = True
        target = reg_list[i]
        top_reg = GetTopRegister(target)
        num = -1
        if IsNumber(target):
            num = hex2int(target)
            t_continue = False
        t_len = len(new_ins_list) - 1
        while t_continue and not t_len < 0:
            head = new_ins_list[t_len]
            if not head:
                break
            if head.extend:
                print_log('\treference value check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
            else:
                print_log('\treference value check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
            if head.mnem == 'pop':
                if IsOpEqual(head.op1, target):
                    break
                elif top_reg and IsOpEqual(head.op1, top_reg):
                    break
                elif not top_reg and IsLowBitSameRegister(head.op1, target):
                    break
                elif top_reg and IsLowBitSameRegister(head.op1, top_reg):
                    break
            elif head.mnem == 'mov':
                if IsOpEqual(head.op1, target):
                    if IsNumber(head.op2):
                        num = hex2int(head.op2)
                        break
                    else:
                        break
                elif top_reg and IsOpEqual(head.op1, top_reg):
                    break
                elif not top_reg and IsLowBitSameRegister(head.op1, target):
                    break
                elif top_reg and IsLowBitSameRegister(head.op1, top_reg):
                    break
            elif head.mnem == 'movzx':
                if IsOpEqual(head.op1, target):
                    break
                elif top_reg and IsOpEqual(head.op1, top_reg):
                    break
                elif not top_reg and IsLowBitSameRegister(head.op1, target):
                    break
                elif top_reg and IsLowBitSameRegister(head.op1, top_reg):
                    break
            elif IsCalcMnem(head.mnem):
                if IsOpEqual(head.op1, target):
                    break
                elif top_reg and IsOpEqual(head.op1, top_reg):
                    break
                elif not top_reg and IsLowBitSameRegister(head.op1, target):
                    break
                elif top_reg and IsLowBitSameRegister(head.op1, top_reg):
                    break
            elif head.mnem == 'xchg':
                if IsOpEqual(head.op1, target) or IsOpEqual(head.op2, target):
                    break
            t_len -= 1
        if num == -1:
            success = False
            break
        else:
            if i == 0:
                result = unsigned32(result + num)
            elif calc_list[i-1] == '+':
                result = unsigned32(result + num)
            else:
                result = result + num
                if result < 0:
                    result = unsigned32(~result+1)
                else:
                    result = unsigned32(result)
        i += 1
    if success:
        #saved_offset_list.append([result, idc.Dword(result)])
        return int2hex(result)
    else:
        return -1

def addHeadinAddList(mnem,op1,op2):
    global add_list
    head = Head(0, mnem, op1, op2)
    add_list.append(head)
    if op2:
        print_log('\t\t\tadd addList : %s %s, %s\n' % (mnem, op1, op2))
    elif op1:
        print_log('\t\t\tadd addList : %s %s\n' % (mnem, op1))
    else:
        print_log('\t\t\tadd addList : %s\n' % mnem)
def addHeadinModifyList(ea, extend, mnem, op1, op2):
    global modifyList
    existHead = findHeadinList(modifyList, ea, extend)
    if existHead:
        modifyList.remove(existHead)
    modifyList.append(Head(ea, mnem, op1, op2, extend))
    if extend:
        if op2:
            print_log('\t\t\tadd modifyList(0x%x(%d)) : %s %s, %s\n' % (ea, extend, mnem, op1, op2))
        elif op1:
            print_log('\t\t\tadd modifyList(0x%x(%d)) : %s %s\n' % (ea, extend, mnem, op1))
        else:
            print_log('\t\t\tadd modifyList(0x%x(%d)) : %s\n' % (ea, extend, mnem))
    else:
        if op2:
            print_log('\t\t\tadd modifyList(0x%x) : %s %s, %s\n' % (ea, mnem, op1, op2))
        elif op1:
            print_log('\t\t\tadd modifyList(0x%x) : %s %s\n' % (ea, mnem, op1))
        else:
            print_log('\t\t\tadd modifyList(0x%x) : %s\n' % (ea, mnem))
def curHeadRemove():
    global cur, isInsert
    isInsert = False
    if cur.extend:
        print_log('\t\t\tcurrent target remove(0x%x(%d))\n' % (cur.ea, cur.extend))
    else:
        print_log('\t\t\tcurrent target remove(0x%x)\n' % cur.ea)
def curHeadRepair():
    global cur, isInsert
    isInsert = True
    if cur.extend:
        print_log('\t\t\tcurrent target repair(0x%x(%d))\n' % (cur.ea, cur.extend))
    else:
        print_log('\t\t\tcurrent target repair(0x%x)\n' % cur.ea)
def GetIndexHeadInfoList(info, target):
    for i in target:
        if info[0] == i[0] and info[1] == i[1]:
            return target.index(i)
    return -1
def addExtendHeadinHead(ea, mnem, op1, op2):
    global extend_info, extend_list
    is_exist = False
    save_point = 0
    for info in extend_info:
        if info[0] == ea:
            info[1] += 1
            save_point = info[1]
            is_exist = True
    if not is_exist:
        extend_info.append([ea, 1])
        extend_list.append([ea, Head(ea, mnem, op1, op2, 1)])
    else:
        for list in extend_list:
            if list[0] == ea:
                list.append(Head(ea, mnem, op1, op2, save_point))
    if op2:
        print_log('\t\t\tHead(0x%x) add extend Head : %s %s, %s\n' % (ea, mnem, op1, op2))
    elif op1:
        print_log('\t\t\tHead(0x%x) add extend Head : %s %s\n' % (ea, mnem, op1))
    else:
        print_log('\t\t\tHead(0x%x) add extend Head : %s\n' % (ea, mnem))
def GetExtendHeadCount(ea):
    global extend_list
    for list in extend_list:
        if list[0] == ea:
            return len(list) - 1
    return 0
def GetNextExtendHead(head):
    global extend_list
    if isinstance(head, int):
        return False
    if not head.extend:
        for list in extend_list:
            if list[0] == head.ea:
                return list[1]
        return False
    else:
        for list in extend_list:
            if list[0] == head.ea:
                it = iter(list)
                it.next()
                for i in range(1, len(list)):
                    head2 = it.next()
                    if head2.extend == head.extend:
                        try:
                            return it.next()
                        except StopIteration:
                            return False
                    elif head2.extend > head.extend:
                        return head2
        return False
def GetExtendHead(ea, n):
    global extend_list
    for list in extend_list:
        if list[0] == ea:
            it = iter(list)
            it.next()
            for i in range(1, len(list)):
                head2 = it.next()
                if head2.extend == n:
                    return head2
            break
def delExtendHead(*args):
    global extend_list,extend_info
    ea = False
    extend = False
    if len(args) == 1:
        ea = args[0].ea
        extend = args[0].extend
    elif len(args) == 2:
        ea = args[0]
        extend = args[1]
    for list in extend_list:
        if list[0] == ea:
            it = iter(list)
            it.next()
            for i in range(1, len(list)):
                head2 = it.next()
                if head2.extend == extend:
                    list.remove(head2)
                    if len(list) == 1:
                        extend_list.remove(list)
                        for info in extend_info:
                            if info[0] == ea:
                                extend_info.remove(info)
                    return
def IsHeadinExceptList(head):
    global except_list
    for info in except_list:
        if info[0] == head.ea and info[1] == head.extend:
            return True
    return False
def GetInfoinFlagList(head):
    global flag_set_list
    for info in flag_set_list:
        if info[0] == head.ea and info[1] == head.extend:
            return info
    return False
def addHeadinExceptList(*args):
    global except_list, extend_list, modifyList
    ea = False
    extend = False
    if len(args) == 1:
        ea = args[0].ea
        extend = args[0].extend
    elif len(args) == 2:
        ea = args[0]
        extend = args[1]
    modifyHead = findHeadinList(modifyList, ea, extend)
    if modifyHead:
        modifyList.remove(modifyHead)
    if extend:
        delExtendHead(ea, extend)
    else:
        except_list.append([ea, extend])
    if extend:
        print_log('\t\t\texcept (0x%x(%d))\n' % (ea, extend))
    else:
        print_log('\t\t\texcept (0x%x)\n' % ea)
def delHeadinExceptList(head):
    global except_list
    for info in except_list:
        if info[0] == head.ea and info[1] == head.extend:
            except_list.remove(info)
def delHeadinTraceList(ea, extend):
    global traceList
    for info in traceList:
        if info[0] == ea and info[1] == extend:
            traceList.remove(info)
def delHeadinTraceList2(ea,extend):
    global traceList2
    for info in traceList2:
        if info[0] == ea and info[1] == extend:
            traceList2.remove(info)
def delInfoInList(l, ea, extend):
   for info in l:
       if info[0] == ea and info[1] == extend:
           l.remove(info)
def findHeadinList(l, ea, extend):
    for head in l:
        if head.ea == ea and head.extend == extend:
            return head
    return False
def unsigned32(n):
    return n & 0xFFFFFFFF
def IsNumber(str):
    if not str:
        return False
    str = str.rstrip('L')
    try:
        if str[len(str)-1] == 'h':
            int(str[:len(str) - 1], 16)
        else:
            int(str, 16)
    except ValueError:
        return False
    return True
def hex2int(h):
    if isinstance(h, long):
        return h
    h = h.rstrip('L')
    if h[len(h)-1] == 'h':
        return int(h[:len(h) - 1], 16)
    else:
        return int(h, 16)
def int2hex(v):
    if v >= 10:
        return '0' + hex(v)[2:].rstrip('L').upper() + 'h'
    else:
        return hex(v)[2:].rstrip('L').upper()
def IsPushMnem(mnem):
    if mnem == 'push' or mnem == 'pushf':
        return True
    return False
def IsCalcMnem(mnem):
    if mnem == 'or' or mnem == 'add' or mnem == 'sub' or mnem == 'xor' or mnem == 'and' \
            or mnem == 'shr' or mnem == 'shl' or mnem == 'not' or mnem == 'neg' \
            or mnem == 'dec' or mnem == 'inc':
        return True
    return False
def IsSingleCalcMnem(mnem):
    if mnem == 'not' or mnem == 'neg' or mnem == 'dec' or mnem == 'inc':
        return True
    return False
def IsNeedOp2CalcMnem(mnem):
    if mnem == 'or' or mnem == 'add' or mnem == 'sub' or mnem == 'xor' or mnem == 'and' \
            or mnem == 'shr' or mnem == 'shl':
        return True
    return False
def GetEspNumber(op):
    temp = ''
    sub = False
    a = op.find('[esp')
    if a == -1:
        return -1
    a += 4
    if not op[a] == '+' and not op[a] == '-':
        return 0
    elif op[a] == '+':
        sub=False
    elif op[a] == '-':
        sub = True
    a += 1
    while not a == len(op) - 1:
        temp += op[a]
        a += 1
        if op[a] == ']':
            break
    temp = hex2int(temp)
    if sub:
        temp = ~temp + 1
    return temp
def FindIndexinList(list, ea, extend):
    i = len(list) - 1
    while not i == 0:
        if list[i][0] == ea and list[i][1] == extend:
            return i
        i -= 1
    return -1
def FindLastIndexEAinList(ea, list):
    i = len(list)-1
    while not i == 0:
        if list[i][0] == ea:
            return i
        i -= 1
def StrFind(str1,str2):
    if not str1 or not str2:
        return False
    if str1.find(str2)==-1:
        return False
    else:
        return True
def IsOpEqual(str1,str2):
    if not str1 or not str2:
        return False
    s1 = str(str1)
    s2 = str(str2)
    reference_reg1 = GetReferenceReg(str1)
    if StrFind(s1, 'dword'):
        s1 = s1[10:]
    elif StrFind(s1, 'word'):
        s1 = s1[9:]
    elif StrFind(s1, 'byte'):
        s1 = s1[9:]
    if StrFind(s2, 'dword'):
        s2 = s2[10:]
    elif StrFind(s2, 'word'):
        s2 = s2[9:]
    elif StrFind(s2, 'byte'):
        s2 = s2[9:]
    if s1 == s2:
        return True
    return False
def IsSameOffset(str1,str2):
    if not str1 or not str2:
        return False
    s_offset1 = GetReferenceReg(str1)
    if not s_offset1:
        return False
    s_offset2 = GetReferenceReg(str2)
    if not s_offset2:
        return False
    offset1 = hex2int(s_offset1)
    offset2 = hex2int(s_offset2)
    if offset1 == offset2:
        return True
    return False
def IsOpInReferenceReg(str1, str2):
    reference_reg = GetReferenceReg(str1)
    if reference_reg:
        if IsNumber(reference_reg):
            if IsNumber(str2):
                if hex2int(reference_reg) == hex2int(str2):
                    return True
        else:
            if StrFind(str1, str2):
                return True
    return False
def IsOpInReferenceRegIncludeSameReg(str1, str2):
    reference_reg = GetReferenceReg(str1)
    if reference_reg:
        if IsNumber(reference_reg):
            if IsNumber(str2):
                if hex2int(reference_reg) == hex2int(str2):
                    return True
        else:
            if IsNotReferenceReg(str2):
                same_reg_list = GetSameRegister(str2)
                if same_reg_list:
                    for same_reg in same_reg_list:
                        if StrFind(str1, same_reg):
                            return True
    return False
def IsOpEqualReferenceReg(str1, str2):
    reference_reg = GetReferenceReg(str1)
    if IsOpEqual(reference_reg, str2):
        return True
    return False
def IsRegsInOpEqualTarget(target, op):
    reference_reg = GetReferenceReg(op)
    if not reference_reg:
        return False
    t_info = GetRegInfo(reference_reg)
    reference_reg_info = []
    for info in t_info:
        if info == 'esp':
            return False
        elif not info == '+' and not info == '-':
            reference_reg_info.append(info)
    for info in reference_reg_info:
        regs = GetSameRegister(info)
        for reg in regs:
            if reg == target:
                return True
    return False
def GetDisasm(head):
    if head.ea == -1:
        return False
    if head.op2:
        return '%s %s, %s' % (head.mnem, head.op1, head.op2)
    elif head.op1:
        return '%s %s' % (head.mnem, head.op1)
    else:
        return '%s' % (head.mnem)

def IsExist(t, l):
    if any(t == a for a in l):
        return True
    else:
        return False
def IsJump(mnem):
    if any(mnem == m for m in JumpList):
        return True
    else:
        return False
def SaveOffsetByteValue(offset, value):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    if isinstance(value, str):
        value = hex2int(value)
    t_val1 = value & 0xFF
    insert1 = False
    for info in saved_offset_list:
        if info[0] == offset:
            info[1] = t_val1
            insert1 = True
    if not insert1:
        saved_offset_list.append([offset, t_val1])
def SaveOffsetWordValue(offset, value):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    if isinstance(value, str):
        value = hex2int(value)
    t_val1 = value & 0xFF
    t_val2 = (value & 0xFF00) >> 8
    insert1 = False
    insert2 = False
    for info in saved_offset_list:
        if info[0] == offset:
            info[1] = t_val1
            insert1 = True
        elif info[0] == (offset+1):
            info[1] = t_val2
            insert2 = True
    if not insert1:
        saved_offset_list.append([offset, t_val1])
    if not insert2:
        saved_offset_list.append([offset+1, t_val2])
def SaveOffsetValue(offset, value):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    if isinstance(value, str):
        value = hex2int(value)
    t_val1 = value & 0xFF
    t_val2 = (value & 0xFF00) >> 8
    t_val3 = (value & 0xFF0000) >> 16
    t_val4 = (value & 0xFF000000) >> 24
    insert1 = False
    insert2 = False
    insert3 = False
    insert4 = False
    for info in saved_offset_list:
        if info[0] == offset:
            info[1] = t_val1
            insert1 = True
        elif info[0] == (offset+1):
            info[1] = t_val2
            insert2 = True
        elif info[0] == (offset+2):
            info[1] = t_val3
            insert3 = True
        elif info[0] == (offset+3):
            info[1] = t_val4
            insert4 = True
    if not insert1:
        saved_offset_list.append([offset, t_val1])
    if not insert2:
        saved_offset_list.append([offset+1, t_val2])
    if not insert3:
        saved_offset_list.append([offset+2, t_val3])
    if not insert4:
        saved_offset_list.append([offset+3, t_val4])
def SaveOffsetWordUnknownValue(offset):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    insert1 = False
    insert2 = False
    for info in saved_offset_list:
        if info[0] == offset:
            info[1] = 'x'
            insert1 = True
        elif info[0] == (offset + 1):
            info[1] = 'x'
            insert2 = True
    if not insert1:
        saved_offset_list.append([offset, 'x'])
    if not insert2:
        saved_offset_list.append([offset + 1, 'x'])
def SaveOffsetByteUnknownValue(offset):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    insert1 = False
    for info in saved_offset_list:
        if info[0] == offset:
            info[1] = 'x'
            insert1 = True
    if not insert1:
        saved_offset_list.append([offset, 'x'])
def SaveOffsetUnknownValue(offset):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    insert1 = False
    insert2 = False
    insert3 = False
    insert4 = False
    for info in saved_offset_list:
        if info[0] == offset:
            info[1] = 'x'
            insert1 = True
        elif info[0] == (offset + 1):
            info[1] = 'x'
            insert2 = True
        elif info[0] == (offset + 2):
            info[1] = 'x'
            insert3 = True
        elif info[0] == (offset + 3):
            info[1] = 'x'
            insert4 = True
    if not insert1:
        saved_offset_list.append([offset, 'x'])
    if not insert2:
        saved_offset_list.append([offset + 1, 'x'])
    if not insert3:
        saved_offset_list.append([offset + 2, 'x'])
    if not insert4:
        saved_offset_list.append([offset + 3, 'x'])
def GetSavedOffsetValue(offset):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    for info in saved_offset_list:
        if info[0] == offset:
            return info[1]
    return -1
def GetOffsetDwordValue(offset):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    value1 = GetSavedOffsetValue(offset)
    value2 = GetSavedOffsetValue(offset + 1)
    value3 = GetSavedOffsetValue(offset + 2)
    value4 = GetSavedOffsetValue(offset + 3)
    if isinstance(value1, str):
        print_log('%s ' % value1)
    else:
        print_log('%x ' % value1)
    if isinstance(value1, str):
        print_log('%s ' % value2)
    else:
        print_log('%x ' % value2)
    if isinstance(value1, str):
        print_log('%s ' % value3)
    else:
        print_log('%x ' % value3)
    if isinstance(value4, str):
        print_log('%s\n' % value4)
    else:
        print_log('%x\n' % value4)
    if value1 == -1:
        value1 = idc.Byte(offset)
        saved_offset_list.append([offset, value1])
    elif value1 == 'x':
        return -1
    if value2 == -1:
        value2 = idc.Byte(offset + 1)
        saved_offset_list.append([offset + 1, value2])
    elif value2 == 'x':
        return -1
    if value3 == -1:
        value3 = idc.Byte(offset + 2)
        saved_offset_list.append([offset + 2, value3])
    elif value3 == 'x':
        return -1
    if value4 == -1:
        value4 = idc.Byte(offset + 3)
        saved_offset_list.append([offset + 3, value4])
    elif value4 == 'x':
        return -1
    if isinstance(value1, str):
        print_log('%s ' % value1)
    else:
        print_log('%x ' % value1)
    if isinstance(value1, str):
        print_log('%s ' % value2)
    else:
        print_log('%x ' % value2)
    if isinstance(value1, str):
        print_log('%s ' % value3)
    else:
        print_log('%x ' % value3)
    if isinstance(value4, str):
        print_log('%s\n' % value4)
    else:
        print_log('%x\n' % value4)
    return (value4 << 24) + (value3 << 16) + (value2 << 8) + value1
def GetOffsetWordValue(offset):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    value1 = GetSavedOffsetValue(offset)
    value2 = GetSavedOffsetValue(offset + 1)
    if value1 == -1:
        value1 = idc.Byte(offset)
        saved_offset_list.append([offset, value1])
    elif value1 == 'x':
        return -1
    if value2 == -1:
        value2 = idc.Byte(offset + 1)
        saved_offset_list.append([offset + 1, value2])
    elif value2 == 'x':
        return -1
    return (value2 << 8) + value1
def GetOffsetByteValue(offset):
    global saved_offset_list
    if isinstance(offset, str):
        offset = hex2int(offset)
    value = GetSavedOffsetValue(offset)
    if value == -1:
        value = idc.Byte(offset)
        saved_offset_list.append([offset, value])
    elif value == 'x':
        return -1
    return value
def CanGetOffsetValue(target_offset):
    global new_ins_list, dont_care_not_num_offset_reference
    if not len(new_ins_list) == 0:
        t_len = len(new_ins_list) - 1
        while t_len >= 0:
            head = new_ins_list[t_len]
            if not head:
                break
            if head.extend:
                print_log('\tcan offset value check loop(0x%x(%d)) : %s\n' % (head.ea, head.extend, GetDisasm(head)))
            else:
                print_log('\tcan offset value check loop(0x%x) : %s\n' % (head.ea, GetDisasm(head)))
            if head.mnem == 'push':
                reference_reg = GetReferenceReg(head.op1)
                if reference_reg and not IsNumber(reference_reg):
                    return False
            elif head.mnem == 'mov':
                reference_reg = GetReferenceReg(head.op1)
                reference_reg2 = GetReferenceReg(head.op2)
                if not dont_care_not_num_offset_reference and reference_reg and not IsNumber(reference_reg):
                    return False
                if reference_reg and IsNumber(reference_reg) and hex2int(reference_reg) == hex2int(target_offset):
                    if IsNumber(head.op2):
                        return True
                    else:
                        return False
            elif head.mnem == 'movzx':
                reference_reg = GetReferenceReg(head.op1)
                reference_reg2 = GetReferenceReg(head.op2)
                if not dont_care_not_num_offset_reference and reference_reg and not IsNumber(reference_reg):
                    return False
                if reference_reg and IsNumber(reference_reg) and hex2int(reference_reg) == hex2int(target_offset):
                    return False
            elif head.mnem == 'pop':
                reference_reg = GetReferenceReg(head.op1)
                if not dont_care_not_num_offset_reference and reference_reg and not IsNumber(reference_reg):
                    return False
                if reference_reg and IsNumber(reference_reg) and hex2int(reference_reg) == hex2int(target_offset):
                    return False
            elif IsCalcMnem(head.mnem):
                reference_reg = GetReferenceReg(head.op1)
                reference_reg2 = GetReferenceReg(head.op2)
                if not dont_care_not_num_offset_reference and reference_reg and not IsNumber(reference_reg):
                    return False
                if reference_reg2 and not IsNumber(reference_reg2):
                    return False
                if reference_reg and IsNumber(reference_reg) and hex2int(reference_reg) == hex2int(target_offset):
                    return False
            t_len -= 1
    return True
def GetOffsetDwordValueIfCan(op):
    global FIRST_THUNK_START, FIRST_THUNK_END
    reference_reg = False
    if isinstance(op, long):
        reference_reg = int2hex(op)
        op = '[%s]' % reference_reg
    elif not IsNumber(op):
        reference_reg = GetReferenceReg(op)
    else:
        reference_reg = op
        op = '[%s]' % op
    if hex2int(reference_reg) > 0x3000000 or CanGetOffsetValue(reference_reg):
        result_value = GetOffsetDwordValue(reference_reg)
        offset_int = hex2int(reference_reg)
        if offset_int >= FIRST_THUNK_START and offset_int <= FIRST_THUNK_END:
            return -1
        return result_value
    return -1
def GetOffsetWordValueIfCan(op):
    global new_ins_list, saved_offset_list
    reference_reg = False
    if isinstance(op, long):
        reference_reg = int2hex(op)
        op = '[%s]' % reference_reg
    elif not IsNumber(op):
        reference_reg = GetReferenceReg(op)
    else:
        reference_reg = op
        op = '[%s]' % op
    if CanGetOffsetValue(reference_reg):
        return GetOffsetWordValue(reference_reg)
    return -1
def GetOffsetByteValueIfCan(op):
    global new_ins_list, saved_offset_list
    reference_reg = False
    if isinstance(op, long):
        reference_reg = int2hex(op)
        op = '[%s]' % reference_reg
    elif not IsNumber(op):
        reference_reg = GetReferenceReg(op)
    else:
        reference_reg = op
        op = '[%s]' % op
    if CanGetOffsetValue(reference_reg):
        return GetOffsetByteValue(reference_reg)
    return -1
def IsOpDword(op):
    if len(op) > 5 and op[:5] == 'dword':
        return True
    return False
def IsOpWord(op):
    if len(op) > 4 and op[:4] == 'word':
        return True
    return False
def IsOpByte(op):
    if len(op) > 4 and op[:4] == 'byte':
        return True
    return False
def GetHighWord(op):
    result = op
    if isinstance(result, str):
        result = hex2int(op)
    return result & 0xFFFF0000
def GetLowWord(op):
    result = op
    if isinstance(result, str):
        result = hex2int(op)
    return result & 0xFFFF
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
def GetTopRegister(op):
    if op == 'ax' or op == 'ah' or op == 'al':
        return 'eax'
    elif op == 'bx' or op == 'bh' or op == 'bl':
        return 'ebx'
    elif op == 'cx' or op == 'ch' or op == 'cl':
        return 'ecx'
    elif op == 'dx' or op == 'dh' or op == 'dl':
        return 'edx'
    elif op == 'bp':
        return 'ebp'
    elif op == 'sp':
        return 'esp'
    elif op == 'si':
        return 'esi'
    elif op == 'di':
        return 'edi'
def IsNotReferenceReg(op):
    if not StrFind(op, '['):
        return True
    return False
def IsPointSameRegister(target, op):
    if not isinstance(target, str):
        return False
    same_registers = GetSameRegister(target)
    if same_registers:
        for reg in same_registers:
            if reg == op:
                return True
    return False
def IsPointSameRegInReferenceReg(target, op):
    if not isinstance(target, str):
        return False
    same_registers = GetSameRegister(op)
    if same_registers:
        for reg in same_registers:
            if IsOpInReferenceReg(target, reg):
                return True
    return False
def IsLowBitSameRegister(target, op):
    if op == 'eax':
        if target == 'ax' or target == 'ah' or target == 'al':
            return True
    elif op == 'ebx':
        if target == 'bx' or target == 'bh' or target == 'bl':
            return True
    elif op == 'ecx':
        if target == 'cx' or target == 'ch' or target == 'cl':
            return True
    elif op == 'edx':
        if target == 'dx' or target == 'dh' or target == 'dl':
            return True
    elif op == 'ebp':
        if target == 'bp':
            return True
    elif op == 'esp':
        if target == 'sp':
            return True
    elif op == 'esi':
        if target == 'si':
            return True
    elif op == 'edi':
        if target == 'di':
            return True
    return False
def IsLowBitRegister(op):
    if op == 'ax' or op == 'bx' or op == 'cx' or op == 'dx' or op == 'bp' or op == 'sp' or op == 'si' or op == 'di':
        return True
    elif op == 'ah' or op == 'bh' or op == 'ch' or op == 'dh':
        return True
    elif op == 'al' or op == 'bl' or op == 'cl' or op == 'dl':
        return True
    return False
def IsDwordRegister(op):
    if op == 'eax' or op == 'ebx' or op == 'ecx' or op == 'edx' or op == 'ebp' or op == 'esp' or op == 'esi' or op == 'edi':
        return True
    return False
def IsWordRegister(op):
    if op == 'ax' or op == 'bx' or op == 'cx' or op == 'dx' or op == 'bp' or op == 'sp' or op == 'si' or op == 'di':
        return True
    return False
def IsLowHighRegister(op):
    if op == 'ah' or op == 'bh' or op == 'ch' or op == 'dh':
        return True
    return False
def IsLowLowRegister(op):
    if op == 'al' or op == 'bl' or op == 'cl' or op == 'dl':
        return True
    return False
def GetJmpValue(op):
    if op[:4] == 'loc_':
        return hex2int(op[4:])
    return False
def GetHead(info):
    global insList, ins_list_check_mode, modifyList
    result = False
    if info[1]:
         result = GetExtendHead(info[0], info[1])
    else:
        if ins_list_check_mode:
            if info[0] < len(insList) - 1:
                result = insList[info[0]]
            else:
                return False
        else:
            idc.MakeUnkn(info[0], 0)
            idc.MakeCode(info[0])
            result = Head(info[0])
    modifyHead = findHeadinList(modifyList, result.ea, result.extend)
    if modifyHead:
        result.mnem = modifyHead.mnem
        result.op1 = modifyHead.op1
        result.op2 = modifyHead.op2
    return result
def PrevHead(head):
    global insList, ins_list_check_mode, modifyList, zero_flag, force_jmp_ea
    result = False
    if isinstance(head, long):
        result = Head(idc.NextHead(head))
    else:
        if head.extend > 1:
            result = GetExtendHead(head.ea, head.extend - 1)
        elif head.extend == 1:
            if ins_list_check_mode:
                result = insList[head.ea]
            else:
                result = Head(head.ea)
        else:
            if ins_list_check_mode:
                result = insList[head.ea - 1]
            else:
                result = Head(idc.PrevHead(head.ea))
    modifyHead = findHeadinList(modifyList, result.ea, result.extend)
    if modifyHead:
        result.mnem = modifyHead.mnem
        result.op1 = modifyHead.op1
        result.op2 = modifyHead.op2
    if result.mnem == 'call':
        if result.op1 == '$+5':
            addHeadinModifyList(result.ea, result.extend, 'push', int2hex(result.ea + 5), False)
            result.mnem = 'push'
            result.op1 = int2hex(result.ea + 5)
            result.op2 = False
    return result
def NextHead(head):
    global insList, ins_list_check_mode, modifyList, zero_flag, force_jmp_ea
    result = False
    if isinstance(head, long):
        idc.MakeCode(idc.NextNotTail(head))
        result = Head(idc.NextHead(head))
    else:
        if not force_jmp_ea:
            extend_head = GetNextExtendHead(head)
            if extend_head:
                result = extend_head
            else:
                if ins_list_check_mode:
                    if head.ea < len(insList) - 1:
                        result = insList[head.ea + 1]
                    else:
                        return False
                else:
                    next_ea = idc.NextNotTail(head.ea)
                    idc.MakeCode(next_ea)
                    if IsJump(head.mnem):
                        if not head.mnem == 'jmp' and head.op1 == '$+6':
                            ea = idc.NextHead(head.ea)
                            if not ea == next_ea:
                                idc.MakeUnkn(ea, 0)
                                idc.MakeCode(next_ea)
                                ea = idc.NextHead(head.ea)
                            result = Head(ea)
                        elif head.mnem == 'jmp' and head.op1 == '$+5':
                            ea = idc.NextHead(head.ea)
                            if not ea == next_ea:
                                idc.MakeUnkn(ea, 0)
                                idc.MakeCode(next_ea)
                                ea = idc.NextHead(head.ea)
                            result = Head(ea)
                        elif head.mnem == 'jmp':
                            result = Head(idc.GetOperandValue(head.ea, 0))
                    else:
                        ea = idc.NextHead(head.ea)
                        if not ea == next_ea:
                            idc.MakeUnkn(ea, 0)
                            idc.MakeCode(next_ea)
                            ea = idc.NextHead(head.ea)
                        result = Head(ea)
        else:
            result = Head(force_jmp_ea)
            ins_list_check_mode = False
    modifyHead = findHeadinList(modifyList, result.ea, result.extend)
    if modifyHead:
        result.mnem = modifyHead.mnem
        result.op1 = modifyHead.op1
        result.op2 = modifyHead.op2
    if result.mnem == 'call':
        if result.op1 == '$+5':
            addHeadinModifyList(result.ea, result.extend, 'push', int2hex(result.ea + 5), False)
            result.mnem = 'push'
            result.op1 = int2hex(result.ea + 5)
            result.op2 = False
    return result
def TestNextHead(head):
    global insList, ins_list_check_mode, modifyList, zero_flag, force_jmp_ea
    result = False
    if isinstance(head, long):
        result = Head(idc.NextHead(head))
    else:
        if not force_jmp_ea:
            extend_head = GetNextExtendHead(head)
            if extend_head:
                result = extend_head
            else:
                if ins_list_check_mode:
                    if head.ea < len(insList) - 1:
                        result = insList[head.ea + 1]
                    else:
                        return False
                else:
                    if IsJump(head.mnem):
                        if not head.mnem == 'jmp' and head.op1 == '$+6':
                            result = Head(idc.NextHead(head.ea))
                        elif head.mnem == 'jmp' and head.op1 == '$+5':
                            result = Head(idc.NextHead(head.ea))
                        elif head.mnem == 'jmp':
                            result = Head(idc.GetOperandValue(head.ea, 0))
                    else:
                        result = Head(idc.NextHead(head.ea))
        else:
            result = Head(force_jmp_ea)
    modifyHead = findHeadinList(modifyList, result.ea, result.extend)
    if modifyHead:
        result.mnem = modifyHead.mnem
        result.op1 = modifyHead.op1
        result.op2 = modifyHead.op2
    if result.mnem == 'call':
        if result.op1 == '$+5':
            addHeadinModifyList(result.ea, result.extend, 'push', int2hex(result.ea + 5), False)
            result.mnem = 'push'
            result.op1 = int2hex(result.ea + 5)
            result.op2 = False
    return result

def print_log(str):
    global log_file
    if function_deob_count >= 0:
        log_file.write(str)
def result2insertIns(result):
    for ins in result:
        a = GetReferenceReg(ins.op1)
        if IsWordRegister(ins.op2):
            ins.op1 = 'word ptr [%s]' % a
        elif IsLowHighRegister(ins.op2) and IsLowLowRegister(ins.op2):
            ins.op1 = 'byte ptr [%s]' % a
        if IsWordRegister(ins.op1):
            if IsNumber(ins.op2):
                ins.op2 = int2hex(hex2int(ins.op2) & 0xFFFF)
        elif IsLowHighRegister(ins.op1):
            if IsNumber(ins.op2):
                ins.op2 = int2hex((hex2int(ins.op2) & 0xFF00) >> 8)
        elif IsLowLowRegister(ins.op1):
            if IsNumber(ins.op2):
                ins.op2 = int2hex(hex2int(ins.op2) & 0xFF)
        else:
            if a and not StrFind(ins.op1, 'dword ptr [') and not IsOpWord(ins.op1) and not IsOpByte(ins.op1):
                ins.op1 = 'dword ptr [%s]' % a
            if StrFind(ins.op2, 'dword ptr'):
                ins.op2 = ins.op2[10:]
    return result
def result2lastInsertIns(result):
    patch_ins = []
    for ins in result:
        if ins.mnem == 'mov' and GetReferenceReg(ins.op1) and GetReferenceReg(ins.op2):
            index = result.index(ins)
            if not IsOpDword(ins.op1):
                result.insert(index + 1, Head(0, 'pop', 'dword ptr %s' % ins.op1, False))
            else:
                result.insert(index + 1, Head(0, 'pop', ins.op1, False))
            ins.mnem = 'push'
            if not IsOpDword(ins.op2):
                ins.op1 = 'dword ptr %s' % ins.op2
            else:
                ins.op1 = ins.op2
            ins.op2 = False
    for ins in result:
        patch_ins.append(Head(len(patch_ins), ins.mnem, ins.op1, ins.op2))
    return patch_ins
def assemble(ea, ins):
    global execute_file
    asm_mnem = ins.mnem
    asm_op1 = ins.op1
    asm_op2 = ins.op2
    if ins.mnem == 'call' and not GetReferenceReg(ins.op1) and IsNumber(ins.op1):
        asm_op1 = '0%xh' % unsigned32(hex2int(ins.op1) - ea)
    if ins.op2:
        asm = '%s %s, %s' % (asm_mnem, asm_op1, asm_op2)
    elif ins.op1:
        asm = '%s %s' % (asm_mnem, asm_op1)
    else:
        asm = '%s' % (asm_mnem)
    print '(0x%x) : %s' % (ea, asm)
    idaapi.assemble(ea, 0, 0, True, asm)
    up_count = 1
    op1_reference_reg = GetReferenceReg(ins.op1)
    op1_info = False
    if op1_reference_reg:
        op1_info = GetRegInfo(op1_reference_reg)
    op2_reference_reg = GetReferenceReg(ins.op2)
    op2_info = False
    if op2_reference_reg:
        op2_info = GetRegInfo(op2_reference_reg)
    if not op1_info and not op2_info:
        if IsNumber(ins.op1):
            t_num = hex2int(ins.op1)
            if t_num > 0x7f:
                up_count += 4
            else:
                up_count += 1
        elif ins.op2:
            if not IsLowBitRegister(ins.op1):
                if IsNumber(ins.op2):
                    t_num = hex2int(ins.op2)
                    if t_num > 0x7f:
                        if not ins.mnem == 'mov':
                            if ins.op1 == 'eax':
                                up_count += 4
                            else:
                                up_count += 5
                        else:
                            up_count += 4
                    else:
                        if ins.mnem == 'mov':
                            up_count += 4
                        else:
                            up_count += 2
                else:
                    if ins.mnem == 'movzx':
                        up_count += 2
                    else:
                        up_count += 1
            elif IsWordRegister(ins.op1):
                if IsNumber(ins.op2):
                    t_num = hex2int(ins.op2)
                    if ins.mnem == 'mov':
                        up_count += 3
                    elif IsCalcMnem(ins.mnem):
                        if ins.mnem == 'shl' or ins.mnem == 'shr':
                            if t_num == 1:
                                up_count += 2
                            else:
                                if t_num > 0x7f:
                                    up_count += 4
                                else:
                                    up_count += 3
                        else:
                            if t_num > 0x7f:
                                up_count += 4
                            else:
                                up_count += 3
                    elif ins.mnem == 'cmp':
                        if t_num > 0x7f:
                            if ins.op1 == 'ax':
                                up_count += 3
                            else:
                                up_count += 4
                        else:
                            up_count += 3
                else:
                    if ins.mnem == 'movzx':
                        up_count += 3
                    else:
                        up_count += 2
            elif IsLowHighRegister(ins.op1) or IsLowLowRegister(ins.op1):
                if IsNumber(ins.op2):
                    t_num = hex2int(ins.op2)
                    if ins.mnem == 'mov':
                        up_count += 1
                    elif IsCalcMnem(ins.mnem):
                        if ins.mnem == 'shl' or ins.mnem == 'shr':
                            if t_num == 1:
                                up_count += 1
                            else:
                                up_count += 2
                        else:
                            up_count += 2
                    elif ins.mnem == 'cmp':
                        if ins.op1 == 'al':
                            up_count += 1
                        else:
                            up_count += 2
                else:
                    up_count += 1
        elif not ins.op2:
            if IsSingleCalcMnem(ins.mnem):
                if not ins.mnem == 'inc' and not ins.mnem == 'dec':
                    up_count += 1
            elif IsJump(ins.mnem):
                if not ins.mnem == 'jmp':
                    up_count += 5
                else:
                    up_count += 4
    elif op1_info:
        if op1_info[0] == 'esp':
            up_count += 1
        if len(op1_info) > 2:
            if IsNumber(op1_info[2]):
                t_num = hex2int(op1_info[2])
                if t_num > 0x7f:
                    up_count += 5
                else:
                    up_count += 2
            else:
                up_count += 3
        else:
            if op1_info[0] == 'ebp':
                up_count += 2
            elif IsNumber(op1_info[0]):
                if ins.mnem == 'mov' and IsOpEqual(ins.op2, 'eax'):
                    up_count += 4
                else:
                    up_count += 5
            else:
                up_count += 1
        if IsNumber(ins.op2):
            t_num = hex2int(ins.op2)
            if IsOpByte(ins.op1):
                up_count += 1
            elif IsOpWord(ins.op1):
                up_count += 2
            else:
                if IsCalcMnem(ins.mnem) and (
                        (t_num >= 0x0 and t_num < 0x80) or (t_num <= 0xFFFFFFFF and t_num >= 0xFFFFFF80)):
                    up_count += 1
                else:
                    up_count += 4
            if ins.mnem == 'shr' or ins.mnem == 'shl':
                if t_num == 1:
                    up_count -= 1
        elif IsWordRegister(ins.op2):
            up_count += 1
    elif op2_info:
        if op2_info[0] == 'esp':
            up_count += 1
        if ins.mnem == 'movzx':
            up_count += 1
        if len(op2_info) > 2:
            if IsNumber(op2_info[2]):
                if hex2int(op2_info[2]) > 0x7F:
                    up_count += 5
                else:
                    up_count += 2
            else:
                if op2_info[0] == 'ebp':
                    up_count += 3
                else:
                    up_count += 2
        else:
            if IsWordRegister(ins.op1):
                if op2_info[0] == 'ebp':
                    up_count += 3
                elif IsNumber(op2_info[0]):
                    up_count += 6
                else:
                    up_count += 2
            elif IsLowHighRegister(ins.op1) or IsLowLowRegister(ins.op1):
                if op2_info[0] == 'ebp':
                    up_count += 2
                elif IsNumber(op2_info[0]):
                    up_count += 5
                else:
                    up_count += 1
            else:
                if op2_info[0] == 'ebp':
                    up_count += 2
                elif IsNumber(op2_info[0]):
                    if ins.mnem == 'mov' and ins.op1 == 'eax':
                        up_count += 4
                    else:
                        up_count += 5
                else:
                    up_count += 1
    i = 0
    loc = 0
    for segment in pe.sections:
        start = segment.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        end = segment.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase + segment.Misc_VirtualSize
        if start <= ea and ea < end:
            loc = ea - start
            execute_file.seek(segment.PointerToRawData + loc)
            print '0x%x' % execute_file.tell()
            while i < up_count:
                execute_file.write(chr(idaapi.get_byte(ea + i)))
                i += 1
            break
    return up_count
def insertResult(start_ea, result):
    global patch_list
    ea = start_ea
    for ins in result:
        up_size = assemble(ea, ins)
        ea += up_size
    return ea
def InsertNewInsList(index, head):
    global new_ins_list
    i = index
    while i == len(new_ins_list):
        new_ins_list[i].ea += 1
        i += 1
    new_ins_list.insert(index, head)
def GetPEInfo():
    global execute_file
    return pefile.PE(data=execute_file.read(0x400))
def GetSavedOffsetList():
    global permanent_saved_offset_list, saved_offset_list
    saved_offset_list = []
    for info in permanent_saved_offset_list:
        if isinstance(info[1], str):
            print_log('0x%x : %s\n' % (info[0], info[1]))
        else:
            print_log('0x%x : %x\n' % (info[0], info[1]))
        saved_offset_list.append([info[0], info[1]])
def GetSavedOriginalRegOffsetInfo(op):
    global original_reg_saved_offset_list
    if not op:
        return False
    reference_reg = GetReferenceReg(op)
    offset = False
    if not reference_reg:
        if IsNumber(op):
            offset = hex2int(op)
        else:
            return False
    else:
        offset = hex2int(reference_reg)
    for info in original_reg_saved_offset_list:
        if offset == info[1]:
            return info
    return False
def addHeadInNewInsList(mnem, op1, op2):
    global new_ins_list
    index = len(new_ins_list)
    new_ins_list.append(Head(index, mnem, op1, op2))
    if op2:
        print_log('\t\tadd Head at the tail of new_ins_list(%x) : %s %s, %s\n' % (index, mnem, op1, op2))
    elif op1:
        print_log('\t\tadd Head at the tail of new_ins_list(%x) : %s %s\n' % (index, mnem, op1))
    else:
        print_log('\t\tadd Head at the tail of new_ins_list(%x) : %s\n' % (index, mnem))
def ChangeReturn(result):
    global next_deob_start_point, permanent_saved_offset_list, saved_offset_list
    i = len(result) - 2
    check_type = 0
    push_count = 0
    head = False
    while i >= 0:
        head = result[i]
        if IsPushMnem(head.mnem):
            if push_count == 0:
                if check_type == 0:
                    result.remove(result[i])
                    result[len(result) - 1].mnem = 'call'
                    result[len(result) - 1].op1 = head.op1
                    result[len(result) - 1].op2 = False
                    check_type += 1
                elif check_type == 1:
                    if IsNumber(head.op1):
                        next_deob_start_point = hex2int(head.op1)
                        result.remove(result[i])
                        check_type += 1
                    else:
                        print 'can\'t find next deob start point.'
            else:
                push_count -= 1
        elif head.mnem == 'pop':
            push_count += 1
        elif head.mnem == 'popf':
            push_count += 1
        i -= 1
    new_result = []
    i = 0
    for ins in result:
        new_result.append(Head(i, ins.mnem, ins.op1, ins.op2))
        i += 1
    return new_result
def SaveCurrentInstructions(result, next_ea, count):
    try:
        ins_load_file = open("C:\idalog\load_state.hs", 'wt')
        for ins in result:
            ins_load_file.write('%s\t%s\t%s\n' % (ins.mnem, ins.op1, ins.op2))
        ins_load_file.write('0x%x\t%d' % (next_ea, count))
        ins_load_file.close()
    except Exception, e:
        ins_load_file.close()
def LoadContinueDatas():
    global continue_count, add_ins_list
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
                if op1 == 'False':
                    op1 = False
                if op2 == 'False':
                    op2 = False
                add_ins_list.append(Head(len(add_ins_list), mnem, op1, op2))
            elif size == 2:
                start_ea = int(info[0][2:], 16)
                continue_count = int(info[1])
        ins_load_file.close()
    except Exception, e:
        ins_load_file.close()
    return start_ea
ins_load_file = False

#base variable
test_count = 0
test_add_count = 0
before_result = False
function_deob_end = False
next_deob_start_point = 0
execute_file = open('C:\Nexon\Maple\MapleStory.exe', 'rb+')
FIRST_THUNK_START = 0x26BC000
FIRST_THUNK_END = 0x26BC66C
pe = GetPEInfo()
saved_offset_list = []
permanent_saved_offset_list = []
remain_count = 0
log_file = False
force_stop = False
status_check_conditional_jmp = False
force_jmp_ea = False
over_jmp_mode = False
restrict_jmp = False
waiting_jmp_ea = False
debug_last_ea = 0
insList = []
new_ins_list = []
is_redeop = False
ins_list_check_mode = False
isInsert = True
isEnd = False     #!
new_ins_list = []     #!
add_ins_list = []
except_list = []  #!
cur = 0           #!
modifyList = []   #!
flag_set_list = [] #!
add_list = []     #!
extend_info = []
extend_list = []
zero_flag = False
overflow_flag = False
carry_flag = False
original_reg_saved_offset_list = []
cant_change_because_not_number_offset_list = []
dont_care_not_num_offset_reference = False
is_continue_same = False

#first loop variable
push_count = 0
continue_count = 0
isContinue = True
head2 = cur
traceList = []
traceList2 = []
traceTemp = []
isExchanged = False
isExchangeEncounter = False
isPopMemoryEspEncounter = False
exchangeTarget = ''
exchange_ea = 0
is_cur_op1_known_value = False
is_cur_stack_changed = False
is_cur_stack_used = False
is_cur_target_reg_changed = False
is_cur_target_reg_point_reg_changed = False #push esi / mov esi, eax / mov eax, 34390 (cur_target = esi, point reg = eax)
is_cur_target_reg_known_value = False
cur_stack_reg = False
cur_target_reg = False # push esi (cur_target_reg = esi)
cur_stack_calc_list = []
cur_target_reg_point_reg = False #push esi / mov esi,eax (point_reg = eax)
org_push_reg_mnem = ''
last_target_op_change = []
last_target_push_count = 0
late_except_list = []
can_push_pop_remove = True
can_stack_change_check = True
once_stack_change_register_encounter = False
push_mov_late_except_list = []
push_pop_late_modify_list = []
esp_size_change_late_extend_list = []
push_pattern1_modify_list = [] # push op1 / mov op, [esp+%d] / pop dword ptr [esp] : mov op, [esp+%d-4] / mov [esp] , op1
reserve_esp_modify_list = [] # push esp / mov eax, [esp] encounter pop op1 -> mov eax, [esp] ... mov eax, esp

saveValue = 0
test_record = []
deob_count = False

#second loop variable
compare_str = ''
#third loop variable

def deobfu_base(ea):
    global debug_last_ea, extend_info, restrict_jmp, over_jmp_mode, force_jmp_ea, force_stop, test_count
    global continue_count
    global insList, new_ins_list, is_redeop, add_list, extend_list, flag_set_list, zero_flag
    global isInsert, cur, isEnd, except_list, cur, modifyList #base global variable
    global isContinue, test_add_count, ins_list_check_mode, saved_offset_list, permanent_saved_offset_list, add_ins_list
    global original_reg_saved_offset_list, cant_change_because_not_number_offset_list
    force_stop = False
    if not over_jmp_mode:
        restrict_jmp = False
    except_list = []
    modifyList = []
    flag_set_list = []
    extend_info = []
    extend_list = []
    new_ins_list = []
    original_reg_saved_offset_list = []
    cant_change_because_not_number_offset_list = []
    if len(add_ins_list) > 0:
        for head in add_ins_list:
            new_ins_list.append(Head(head.ea, head.mnem, head.op1, head.op2))
        add_ins_list = []
    insList = []
    saved_offset_list = []
    #GetSavedOffsetList()
    isEnd = False

    if isinstance(ea, list):
        insList = ea
        cur = insList[0]
        is_redeop = True
        ins_list_check_mode = True
    else:
        cur = GetHead([ea, False])
        is_redeop = False
        ins_list_check_mode = False
        print 'remain_count : %d' % (test_count - continue_count)
    while not isEnd:
        force_jmp_ea = False
        temp_disasm = GetDisasm(cur)
        if not temp_disasm is False:
            if cur.extend:
                print_log('check 0x%x(%d) : %s\n' % (cur.ea, cur.extend, temp_disasm))
            else:
                print_log('check 0x%x : %s\n' % (cur.ea,temp_disasm))
        flag_info = GetInfoinFlagList(cur)
        if flag_info:
            if flag_info[1]:
                zero_flag = True
            else:
                zero_flag = False
        if not IsHeadinExceptList(cur):
            isInsert = True
            isContinue = True
            add_list=[]
            #push deobfuscation algorithm
            if not cur.mnem:
                if cur.op1 == cur.op2:
                    curHeadRemove()
            elif IsPushMnem(cur.mnem):
                push_deob()
            elif cur.mnem == 'pop':
                pop_deob()
            #add sub deobfuscation algorithm
            elif IsCalcMnem(cur.mnem):
                if cur.mnem == 'add' or cur.mnem == 'sub':
                    addsub_deob()
                elif cur.mnem == 'xor':
                    xor_deob()
                else:
                    calc_deob()
            elif cur.mnem == 'xchg':
                xchg_deob()
            elif cur.mnem == 'rdtsc':
                isInsert = False
            elif cur.mnem == 'pusha':
                pusha_deob()
            elif cur.mnem == 'mov':
                mov_deob()
            elif cur.mnem == 'movzx':
                movzx_deob()
            elif cur.mnem == 'cmp':
                cmp_deob()
            elif cur.mnem == 'cmpxchg':
                cmpxchg_deob()
            elif IsJump(cur.mnem):
                jump_deob()
            elif cur.mnem == 'retn':
                force_stop = True
            elif cur.mnem == 'call':
                if cur.op1 == '$+5':
                    curHeadRemove()
            if isInsert:
                if cur.op2:
                    print_log('\tins list append(0x%x) : %s %s, %s\n'%(len(new_ins_list),cur.mnem,cur.op1,cur.op2))
                elif cur.op1:
                    print_log('\tins list append(0x%x) : %s %s\n' % (len(new_ins_list),cur.mnem, cur.op1))
                else:
                    print_log('\tins list append(0x%x) : %s\n' % (len(new_ins_list),cur.mnem))
                new_ins_list.append(Head(len(new_ins_list), cur.mnem, cur.op1, cur.op2))
                if cur.mnem == 'mov':
                    op1_reference_reg = GetReferenceReg(cur.op1)
                    if op1_reference_reg and IsNumber(op1_reference_reg):
                        if IsOpWord(cur.op1):
                            if IsNumber(cur.op2):
                                SaveOffsetWordValue(op1_reference_reg, cur.op2)
                            else:
                                SaveOffsetWordUnknownValue(op1_reference_reg)
                        elif IsOpByte(cur.op1):
                            if IsNumber(cur.op2):
                                SaveOffsetByteValue(op1_reference_reg, cur.op2)
                            else:
                                SaveOffsetByteUnknownValue(op1_reference_reg)
                        else:
                            if IsNumber(cur.op2):
                                SaveOffsetValue(op1_reference_reg, cur.op2)
                            else:
                                SaveOffsetUnknownValue(op1_reference_reg)
                    op2_reference_reg = GetReferenceReg(cur.op2)
                    if op1_reference_reg and IsNumber(op1_reference_reg) and not op2_reference_reg and \
                        not IsNumber(cur.op2) and not cur.op2 == 'esp':
                        original_reg_saved_offset_list.append([len(new_ins_list) - 1, hex2int(op1_reference_reg), cur.op2])
                elif cur.mnem == 'movzx':
                    op1_reference_reg = GetReferenceReg(cur.op1)
                    if op1_reference_reg and IsNumber(op1_reference_reg):
                        SaveOffsetUnknownValue(op1_reference_reg)
                elif cur.mnem == 'calc':
                    op1_reference_reg = GetReferenceReg(cur.op1)
                    if op1_reference_reg and IsNumber(op1_reference_reg):
                        SaveOffsetUnknownValue(op1_reference_reg)
                elif cur.mnem == 'pop':
                    op1_reference_reg = GetReferenceReg(cur.op1)
                    if op1_reference_reg and IsNumber(op1_reference_reg):
                        SaveOffsetUnknownValue(op1_reference_reg)
                if cur.extend:
                    delExtendHead(cur)
                for head in add_list:
                    if head.op2:
                        print_log('\tins list append(0x%x) : %s %s, %s\n' % (len(new_ins_list), head.mnem, head.op1, head.op2))
                    elif head.op1:
                        print_log('\tins list append(0x%x) : %s %s\n' % (len(new_ins_list), head.mnem, head.op1))
                    else:
                        print_log('\tins list append(0x%x) : %s\n' % (len(new_ins_list), head.mnem))
                    new_ins_list.append(Head(len(new_ins_list), head.mnem, head.op1, head.op2))
            else:
                if cur.extend:
                    delExtendHead(cur)
        else:
            if cur.extend:
                delExtendHead(cur)
                print_log('\texcept : 0x%x(%d)\n' % (cur.ea, cur.extend))
            else:
                print_log('\texcept : 0x%x\n' % cur.ea)
            delHeadinExceptList(cur)
        if force_jmp_ea:
            ins_list_check_mode = False
        if not ins_list_check_mode and not force_stop:
            if force_jmp_ea:
                debug_last_ea = GetHead([force_jmp_ea, False])
            else:
                debug_last_ea = TestNextHead(cur)
        if not is_redeop:
            if not cur.extend:
                continue_count += 1
            if continue_count >= test_count:
                if len(except_list) == 0 and len(modifyList) == 0:
                    isEnd = True
                    break
                else:
                    test_add_count += 1
        else:
            if not ins_list_check_mode:
                if continue_count >= test_count:
                    if len(except_list) == 0 and len(modifyList) == 0:
                        isEnd = True
                        break
                    else:
                        test_add_count += 1
                if not cur.extend:
                    continue_count += 1
        if force_stop:
            break
        cur = NextHead(cur)
        if not cur:
            isEnd = True
            break
        else:
            if not over_jmp_mode:
                if restrict_jmp:
                    if cur.mnem == 'jz' and not IsOpEqual(cur.op1, '$+6'):
                        isEnd = True
                        break
                    elif cur.mnem == 'jbe' and not IsOpEqual(cur.op1, '$+6'):
                        isEnd = True
                        break
                    elif cur.mnem == 'jmp':
                        isEnd = True
                        break
            modifyHead = findHeadinList(modifyList, cur.ea, cur.extend)
            if modifyHead:
                modifyList.remove(modifyHead)
    for ea_info in except_list:
        if ea_info[1]:
            print_log('exception %x(%d)\n' % (ea_info[0], ea_info[1]))
        else:
            print_log('exception %x\n' % ea_info[0])
    print_log('---------modifyList---------\n')
    for head in modifyList:
        if head.op2:
            print_log('0x%x : %s %s %s\n' % (head.ea, head.mnem, head.op1, head.op2))
        elif head.op1:
            print_log('0x%x : %s %s\n' % (head.ea, head.mnem, head.op1))
        else:
            print_log('0x%x : %s\n' % (head.ea, head.mnem))
    return new_ins_list

try:
    result_save_mode = False
    result_load_mode = True
    save_last_result = []
    function_deob_count = 0
    log_file = open("C:\idalog\log3.txt", 'w')
    remain_count = test_count = 19625 #18919(ok) 19525(ok) 19825 #20306
    over_jmp_mode = True
    original_start = 0x3487D97  # 1600(ok) 961(ok)(2DA57B8)
    test = 0x2DA57C5  # 2DA4D60(820) #0x2DA57C5(640) #0x2DA64A3(109)
    test2 = 0x2DA4CE6
    test3 = 0x2DA5EFC
    #result = result2insertIns(deobfu_base(test3))
    #result = result2insertIns(deobfu_base(test))
    #result = result2insertIns(deobfu_base(test2))
    if result_load_mode:
        start_ea = LoadContinueDatas()
        result = result2insertIns(deobfu_base(start_ea))
    else:
        result = result2insertIns(deobfu_base(original_start))
    before_result = list(result)

    print_log('\n')
    for ins in result:
        if not ins.op1:
            print_log('result(0x%x) : %s\n' % (ins.ea, ins.mnem))
        elif not ins.op2:
            print_log('result(0x%x) : %s %s\n' % (ins.ea, ins.mnem, ins.op1))
        else:
            print_log('result(0x%x) : %s %s, %s\n' % (ins.ea, ins.mnem, ins.op1, ins.op2))
    deob_count = 0
    write_ea = 0x3BBC000
    while not deob_count == 2000: #120
        print_log('\n\n\n\n')
        if function_deob_end:
            status_check_conditional_jmp = False
            ins_list_check_mode = False
            print_log('-----------------------(%d)new deobfuscation start-----------------------\n' % deob_count)
            result = result2insertIns(deobfu_base(next_deob_start_point))
            function_deob_end = False
        else:
            print_log('-----------------------(%d)redeobfuscation-----------------------\n' % deob_count)
            result = result2insertIns(deobfu_base(result))
            dont_care_not_num_offset_reference = False
        if len(result) == 0:
            break
        if len(result) == len(before_result):
            i = len(result) - 1
            same_result = True
            while i >= 0:
                if not (result[i].mnem == before_result[i].mnem and result[i].op1 == before_result[i].op1 and result[i].op2 == before_result[i].op2):
                    same_result = False
                i -= 1
            if same_result:
                if len(result) > 0:
                    if result[len(result) - 1].mnem == 'retn':
                        result = ChangeReturn(result)
                        if next_deob_start_point:
                            function_deob_end = True
                            if continue_count >= test_count:
                                debug_last_ea = Head(next_deob_start_point)
                                break
                            for head in result:
                                add_ins_list.append(Head(head.ea, head.mnem, head.op1, head.op2))
                            function_deob_count += 1
                        else:
                            for ins in result:
                                if not ins.op1:
                                    print_log('result(0x%x) : %s\n' % (ins.ea, ins.mnem))
                                elif not ins.op2:
                                    print_log('result(0x%x) : %s %s\n' % (ins.ea, ins.mnem, ins.op1))
                                else:
                                    print_log('result(0x%x) : %s %s, %s\n' % (ins.ea, ins.mnem, ins.op1, ins.op2))
                            break
                    else:
                        last_ins = result[len(result)-1]
                        if is_continue_same:
                            break
                        if IsJump(last_ins.mnem):
                            dont_care_not_num_offset_reference = True
                            is_continue_same = True
                        elif cant_change_because_not_number_offset_list:
                            for info in cant_change_because_not_number_offset_list:
                                result[info[0]].mnem = info[1]
                                result[info[0]].op1 = info[2]
                                result[info[0]].op2 = info[3]
                            is_continue_same = True
                        else:
                            break
                else:
                    break
            else:
                is_continue_same = False
        before_result = list(result)
        for ins in result:
            if not ins.op1:
                print_log('result(0x%x) : %s\n' % (ins.ea, ins.mnem))
            elif not ins.op2:
                print_log('result(0x%x) : %s %s\n' % (ins.ea, ins.mnem, ins.op1))
            else:
                print_log('result(0x%x) : %s %s, %s\n' % (ins.ea, ins.mnem, ins.op1, ins.op2))
        deob_count += 1
    result = result2lastInsertIns(result)
    print_log('\n\n\n-------------- result --------------\n')
    for ins in result:
        if not ins.op1:
            print_log('result(0x%x) : %s\n' % (ins.ea, ins.mnem))
        elif not ins.op2:
            print_log('result(0x%x) : %s %s\n' % (ins.ea, ins.mnem, ins.op1))
        else:
            print_log('result(0x%x) : %s %s, %s\n' % (ins.ea, ins.mnem, ins.op1, ins.op2))
    write_ea = insertResult(write_ea, result)
    jmp_head = Head(0, 'jmp', '0%xh' % unsigned32(debug_last_ea.ea - write_ea), False)
    assemble(write_ea, jmp_head)
    if result_save_mode:
        SaveCurrentInstructions(result, debug_last_ea.ea, test_count + test_add_count)

    print_log('last ea : 0x%x\n' % debug_last_ea.ea)
    print_log('test count : %d' % (test_count + test_add_count))
    print 'last ea : 0x%x' % debug_last_ea.ea
    print 'deop check %d instruction' % (test_count + test_add_count)
    print "deobfuscation end!"
    for record in test_record:
        print 'record : %s 0x%x' % (record[0], record[1])
    log_file.close()
    execute_file.close()
except Exception, e:
    execute_file.close()
    log_file.close()
    traceback.print_exc()