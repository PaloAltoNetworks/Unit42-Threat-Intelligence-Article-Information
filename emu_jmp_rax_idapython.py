from unicorn import *
from unicorn.x86_const import *

idaapi.msg_clear()


"""
This IDA Pro Python script emulates x86-64 code using Unicorn Engine to analyze dynamic jmp 
instructions. It extracts values from registers, particularly RAX, after emulation to help
with reverse engineering. The script also handles data segment mapping and provides dummy
stack setup for proper emulation.
"""


def emulate_code(CODE_HEX, ADDRESS):   
    CODE = bytes.fromhex(CODE_HEX)
    TEXT_SEG = 0x180001000
    
    #read bytes from .data segment
    data_segm = idaapi.get_segm_by_name(".data")
    DATA_SEGMENT = idaapi.get_bytes(data_segm.start_ea, data_segm.end_ea - data_segm.start_ea).hex()
    
    # Compute destination address when CF and ZF are 0s
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(TEXT_SEG, 0x200000)
    mu.mem_write(ADDRESS, CODE)
    eflags = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags |= 0x1 
    eflags |= 0x40 
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)
    mu.mem_write(0x18019A000,bytes.fromhex(DATA_SEGMENT)) #create .data segment
    mu.reg_write(UC_X86_REG_RAX, 0)
    # Emulate code
    mu.emu_start(ADDRESS, ADDRESS + len(CODE))
    # Read back results
    rax_1 = mu.reg_read(UC_X86_REG_RAX)

    # Compute destination address when CF and ZF are 1s
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(TEXT_SEG, 0x200000)
    mu.mem_write(ADDRESS, CODE)
    eflags = mu.reg_read(UC_X86_REG_EFLAGS)
    eflags &= ~0x1  
    eflags &= ~0x40  
    mu.reg_write(UC_X86_REG_EFLAGS, eflags)
    mu.mem_write(0x18019A000,bytes.fromhex(DATA_SEGMENT))
    mu.reg_write(UC_X86_REG_RAX, 0)
    # Emulate code
    mu.emu_start(ADDRESS, ADDRESS + len(CODE))
    # Read back results
    rax_0 = mu.reg_read(UC_X86_REG_RAX)
    return (rax_0, rax_1)

def setup_emulate(JMP_RAX):
    emu_start = JMP_RAX
    loop = 9
    for i in range(loop):
        emu_start = idc.prev_head(emu_start)    #look for the entry of the dispatcher
    CODE_HEX_len = JMP_RAX - emu_start
    CODE_HEX = idaapi.get_bytes(emu_start, CODE_HEX_len).hex()
    return (CODE_HEX, emu_start)


def jmp_rax_patch(emu_start, jmp_ea, tar_0_ea, tar_1_ea):
    offset0 = tar_0_ea - emu_start - 6
    print(f"{emu_start:X} offset = {offset0}")
    offset0 = offset0.to_bytes(4,'little')
    jnz_buf = "0F85" + offset0.hex()
    jnz_buf = bytes.fromhex(jnz_buf)
    idaapi.patch_bytes(emu_start,jnz_buf)
    cur_ea = emu_start + len(jnz_buf)
    offset1 = tar_1_ea - cur_ea - 5 
    print(f"{cur_ea:X} offset = {offset1}")
    offset1 = offset1.to_bytes(4,'little')
    jmp_buf = "E9" + offset1.hex()
    jmp_buf = bytes.fromhex(jmp_buf)
    idaapi.patch_bytes(cur_ea,jmp_buf)
    cur_ea = cur_ea + len(jmp_buf)
    while cur_ea != jmp_ea + 2:
        idaapi.patch_byte(cur_ea,0x90)
        cur_ea = idc.next_addr(cur_ea)
        

def fix_function(start, end):
    ea = start
    while ea < end:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE)
        ea = idc.next_addr(ea)
    ea = start
    while ea < end:
        len = idaapi.create_insn(ea)
        ea = len + ea  
    ida_funcs.add_func(start, end)


# Get the current function boundaries
f = idaapi.get_func(idaapi.get_screen_ea())
if f is None:
    print("No function found at current location.")
    exit()

start_ea = f.start_ea
end_ea = f.end_ea

ea = start_ea
#print(f'{start_ea:X} {end_ea:X} {ea:X}')
# Iterate through all instructions in the function
while ea < end_ea:
    ea = next_head(ea)
    #print(f'current ea = {ea:X}')
    if not idc.is_code(idc.get_full_flags(ea)):
        continue
    insn = idaapi.insn_t()
    length = idaapi.decode_insn(insn, ea)
    if length == 0:
        continue
    # Check for 'Jmp Rax' instruction
    if insn.itype == idaapi.NN_jmpni: # or insn.itype == idaapi.NN_callni:
        # Verify operand is EAX register
        op = insn.ops[0] #single operand instruction
        #print(f'1current ea = {insn.ea:X}')
        if op.type == idaapi.o_reg:
            if op.reg == 0: # Rax == 0
                CODE_HEX, emu_start = setup_emulate(ea)
                rax_0, rax_1 = emulate_code(CODE_HEX, emu_start)
                print(f'0x{emu_start:X}, 0x{ea:X}, 0x{rax_0:X}, 0x{rax_1:X}')
                jmp_rax_patch(emu_start, ea, rax_0, rax_1)

fix_function(start_ea, end_ea)
