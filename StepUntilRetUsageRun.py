import idc
import idaapi
def step_until_ret_usage_run():
    mnem = idc.GetMnem(idc.here())
    while not mnem == 'retn':
        idaapi.step_until_ret()
        idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)
        mnem = idc.GetMnem(idc.here())

try:
    step_until_ret_usage_run()
except Exception, e:
    print 'ha'