from unicorn import *
from unicorn.x86_const import *
from capstone import *

idaapi.msg_clear()


"""
This IDA Pro Python script emulates x86-64 code using Unicorn Engine to analyze dynamic call 
instructions. It extracts values from registers, particularly RAX, after emulation to help
with reverse engineering. The script also handles data segment mapping and provides dummy
stack setup for proper emulation.
"""


def emulate_code(CODE_HEX, ADDRESS):   
    CODE = bytes.fromhex(CODE_HEX)
    TEXT_SEG = 0x180001000
    DATA_SEG = 0x18019A000
        
    def skip_instr_hook(uc, address, size):
        global RAX
        RAX = mu.reg_read(UC_X86_REG_RAX)
        code = mu.mem_read(address, size)        
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for ins in md.disasm(code, address):
            if ins.mnemonic == "call" or ins.mnemonic == "lea" or ins.mnemonic == "jmp" :
                uc.reg_write(UC_X86_REG_RIP, address + ins.size)

    #read bytes from .data segment
    data_segm = idaapi.get_segm_by_name(".data")
    DATA_SEGMENT = get_bytes(data_segm.start_ea, data_segm.end_ea - data_segm.start_ea).hex()

    # Initialize emulator in X86-64bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(TEXT_SEG, 0x184000)
    mu.mem_write(ADDRESS, CODE)

    #Setup Data segment
    mu.mem_map(DATA_SEG, 0x20000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_write(DATA_SEG,bytes.fromhex(DATA_SEGMENT))
    mu.reg_write(UC_X86_REG_RCX,0x1801A1000)
    mu.hook_add(UC_HOOK_CODE, skip_instr_hook)
    
    #Setup Dummy Stack
    stack_addr = 0x7fff0000
    mu.mem_map(stack_addr, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
    mu.reg_write(UC_X86_REG_RBP, stack_addr+0x1000)
    mu.reg_write(UC_X86_REG_RSP, stack_addr+0x2000)

    # Emulate code
    try:
        mu.emu_start(ADDRESS, ADDRESS + len(CODE))
    except Exception as e:
        return (RAX)

    # Read back results
    rax_0 = mu.reg_read(UC_X86_REG_RAX)
    return (rax_0)


def set_callee_address(call_ea, callee_ea):
    # Use Intel-specific netnode name
    nname1 = "$ vmm functions"
    n = ida_netnode.netnode(nname1)
    # Store callee EA directly (workaround for missing ea2node)
    n.altset_ea(call_ea, callee_ea+1)
    # Reanalyze the instruction to update internal metadata
    ida_auto.plan_ea(call_ea)
    # Add a user cross-reference
    ida_xref.add_cref(call_ea, callee_ea, ida_xref.fl_CN | ida_xref.XREF_USER)
    # Refresh IDA views correctly
    ida_kernwin.refresh_idaview_anyway()
    return True


def set_hexrays_comment(address, text):
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts() 
    cfunc.refresh_func_ctext()


def setup_emulate(CALL_RAX, loop):
    emu_start = CALL_RAX
    for i in range(loop):
        emu_start = idc.prev_head(emu_start)
    CODE_HEX_len = CALL_RAX - emu_start
    CODE_HEX = idaapi.get_bytes(emu_start, CODE_HEX_len).hex()
    return (CODE_HEX, emu_start)


f = idaapi.get_func(idaapi.get_screen_ea())
if f is None:
    print("No function found at current location.")
    exit()
start_ea = f.start_ea
end_ea = f.end_ea
ea = start_ea
while ea < end_ea:
    ea = next_head(ea)
    if not idc.is_code(idc.get_full_flags(ea)):
        continue
    insn = idaapi.insn_t()
    length = idaapi.decode_insn(insn, ea)
    if length == 0:
        continue
    if insn.itype == idaapi.NN_callni:
        op = insn.ops[0]
        if op.type == idaapi.o_reg:
            if op.reg == 0:
                for loop in range(4, 65):
                    CODE_HEX, emu_start = setup_emulate(ea, loop)
                    rax_0  = emulate_code(CODE_HEX, emu_start)
                    if rax_0 > 0x180001000 and rax_0 < 0x180185000:
                        print(f'emu_start :: 0x{emu_start:X}  call_rax :: 0x{ea:X} RAX :: 0x{rax_0:X} {idaapi.get_name(rax_0)} {loop}')
                        idaapi.set_cmt(ea, f'{idaapi.get_name(rax_0)}',0)
                        set_callee_address(ea, rax_0)
                        set_hexrays_comment(ea, idaapi.get_name(rax_0))
                        break