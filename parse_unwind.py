import idaapi
import idautils
import idc

# Set this flag to True to enable debug prints
DEBUG = True

def debug_print(msg):
    """Print debug messages if DEBUG flag is set."""
    if DEBUG:
        print(msg)

def get_image_base():
    """Get the image base address of the loaded binary."""
    image_base = idaapi.get_imagebase()
    debug_print(f"Image base: 0x{image_base:X}")
    return image_base

def get_pdata_segment():
    """Get the .pdata segment."""
    seg = idaapi.get_segm_by_name(".pdata")
    if not seg:
        print("Error: .pdata section not found.")
        return None, None
    debug_print(f".pdata segment found: start=0x{seg.start_ea:X}, end=0x{seg.end_ea:X}")
    return seg.start_ea, seg.end_ea

def parse_scope_table(scope_table_addr, num_entries):
    """Parse the C_SCOPE_TABLE structure."""
    scopes = []
    entry_size = 2 * 4  # Each entry is two 4-byte values (begin, end addresses)

    for i in range(num_entries):
        try:
            begin_addr = idc.get_wide_dword(scope_table_addr + i * entry_size)
            end_addr = idc.get_wide_dword(scope_table_addr + i * entry_size + 4)
            handler_addr = idc.get_wide_dword(scope_table_addr + (i * entry_size + 8))
            if begin_addr == 0xFFFFFFFF or end_addr == 0xFFFFFFFF or handler_addr == 0xFFFFFFFF:
                debug_print(f"Invalid address in scope table at entry {i}")
                break
            scopes.append((begin_addr, end_addr, handler_addr))
            debug_print(f"Scope Table Entry {i}: Begin=0x{begin_addr:X}, End=0x{end_addr:X}, Handler=0x{handler_addr:X}")
        except Exception as e:
            debug_print(f"Exception parsing scope table entry {i}: {e}")
            break

    return scopes

def parse_unwind_code(addr, count):
    unwind_codes = []
    for i in range(count):
        code_offset = ida_bytes.get_byte(addr + i * 2)
        unwind_op_info = ida_bytes.get_byte(addr + i * 2 + 1)
        operation = unwind_op_info & 0x0F
        info = unwind_op_info >> 4
        unwind_codes.append((code_offset, operation, info))
    return unwind_codes

def parse_unwind_info(addr):
    version_flags = ida_bytes.get_byte(addr)
    version = version_flags & 0b111
    flags = version_flags >> 3

    size_of_prolog = ida_bytes.get_byte(addr + 1)
    count_of_unwind_codes = ida_bytes.get_byte(addr + 2)

    frame_reg_offset = ida_bytes.get_byte(addr + 3)
    frame_register = frame_reg_offset & 0b1111
    frame_register_offset = frame_reg_offset >> 4

    unwind_codes = parse_unwind_code(addr + 4, count_of_unwind_codes)
    
    # Initialize stack allocation size
    stack_allocation_size = 0
    
    # Parse non-volatile registers and stack allocation size
    reg_names = [
        "RAX", "RCX", "RDX", "RBX", 
        "RSP", "RBP", "RSI", "RDI", 
        "R8", "R9", "R10", "R11", 
        "R12", "R13", "R14", "R15"
    ]
    non_volatile_registers = []
    i = 0
    while i < len(unwind_codes):
        code = unwind_codes[i]
        if code[1] == 0:  # UWOP_PUSH_NONVOL
            reg = reg_names[code[2]]
            non_volatile_registers.append(reg)
        elif code[1] == 4 or code[1] == 5:  # UWOP_SAVE_NONVOL or UWOP_SAVE_NONVOL_FAR
            reg = reg_names[code[2]]
            non_volatile_registers.append(f"{reg} (at offset {code[0]})")
        elif code[1] == 1:  # UWOP_ALLOC_LARGE
            if code[2] == 0:
                stack_allocation_size += ida_bytes.get_wide_word(addr + 4 + i * 2 + 2)
                i += 2  # Skip the next 2 bytes as they are part of the current operation
            else:
                stack_allocation_size += ida_bytes.get_wide_dword(addr + 4 + i * 2 + 2)
                i += 2  # Skip the next 4 bytes as they are part of the current operation
        elif code[1] == 2:  # UWOP_ALLOC_SMALL
            stack_allocation_size += (code[2] + 1) * 8
        i += 1

    return {
        "Version": version,
        "Flags": flags,
        "SizeOfProlog": size_of_prolog,
        "CountOfUnwindCodes": count_of_unwind_codes,
        "FrameRegister": frame_register,
        "FrameRegisterOffset": frame_register_offset,
        "UnwindCodes": unwind_codes,
        "NonVolatileRegisters": non_volatile_registers,
        "StackAllocationSize": stack_allocation_size
    }

def suggest_calling_convention(non_volatile_registers, stack_allocation_size):
    """Suggest a calling convention based on the parsed information.
    Calling Convention Suggestion: Added suggest_calling_convention function that suggests a calling
    convention based on saved registers and stack allocation size.
    If RBX, RDI, and RSI are saved, it suggests __fastcall.
    If there is stack allocation, it suggests __stdcall.
    Otherwise, it defaults to __cdecl."""

    if "RBX" in non_volatile_registers and "RDI" in non_volatile_registers and "RSI" in non_volatile_registers:
        return "__fastcall"
    elif stack_allocation_size > 0:
        return "__stdcall"
    else:
        return "__cdecl"

def process_function(func_start, image_base, pdata_start, pdata_end):
    """Process a single function and add comments based on UNWIND_INFO."""
    for addr in range(pdata_start, pdata_end, 12):
        start_rva = idc.get_wide_dword(addr)
        end_rva = idc.get_wide_dword(addr + 4)
        unwind_info_rva = idc.get_wide_dword(addr + 8)

        if func_start == image_base + start_rva:
            unwind_info_addr = image_base + unwind_info_rva
            unwind_info = parse_unwind_info(unwind_info_addr)
            if unwind_info is None:
                continue
            
            non_volatile_regs = ', '.join(unwind_info['NonVolatileRegisters'])
            calling_convention = suggest_calling_convention(unwind_info['NonVolatileRegisters'], unwind_info['StackAllocationSize'])

            comment = (
                "UnwindInfo:\n"
                f"Version: {unwind_info['Version']}\n"
                f"Flags: {unwind_info['Flags']}\n"
                f"SizeOfProlog: {unwind_info['SizeOfProlog']}\n"
                f"CountOfUnwindCodes: {unwind_info['CountOfUnwindCodes']}\n"
                f"FrameRegister: {unwind_info['FrameRegister']}\n"
                f"FrameRegisterOffset: {unwind_info['FrameRegisterOffset']}\n"
                f"Stack Allocation Size: {unwind_info['StackAllocationSize']} bytes\n"
                f"Non-volatile Registers: {non_volatile_regs}\n"
                f"Suggested Calling Convention: {calling_convention}\n"
            )

            idc.set_func_cmt(func_start, comment, 1)
            debug_print(f"Added comment to function at 0x{func_start:X} with calling convention suggestion: {calling_convention}")
            break

def add_comments():
    """Add comments to each function based on UNWIND_INFO."""
    image_base = get_image_base()
    pdata_start, pdata_end = get_pdata_segment()
    if pdata_start is None:
        return
    
    for func_start in idautils.Functions():
        process_function(func_start, image_base, pdata_start, pdata_end)

add_comments()
print("Finished adding comments based on UNWIND_INFO.")
