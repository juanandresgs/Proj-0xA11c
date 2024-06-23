import idaapi
import idautils
import idc
import ida_bytes

# ------------------------------------------------------------
# Flags
# ------------------------------------------------------------

# Set this flag to True to enable debug prints
DEBUG = True
function_without_unwind = []
IS_PRINT_NON_UNWIND_FUNCTION = False

# ------------------------------------------------------------
# Utils
# ------------------------------------------------------------

def get_architecture_info():
    # Access the global inf structure
    info = idaapi.get_inf_structure()

    # Retrieve and print the processor type
    processor_type = info.procname
    bitness = info.is_64bit() and "64-bit" or info.is_32bit() and "32-bit" or "16-bit"

    # Determine the architecture
    architecture = ""
    if processor_type == "metapc":
        if bitness == "64-bit":
            architecture = "x86-64"
        else:
            architecture = "x86"
    elif "arm" in processor_type:
        if bitness == "64-bit":
            architecture = "ARM64"
        else:
            architecture = "ARM"
    else:
        architecture = "Unknown"

    debug_print("Processor type:", processor_type)
    debug_print("Architecture:", architecture)
    debug_print("Bitness:", bitness)
    
    return(architecture, bitness)

def debug_print(msg):
    """Print debug messages if DEBUG flag is set."""
    if DEBUG:
        print(msg)
        
def error_print(msg):
    """Print debug messages if DEBUG flag is set."""
    print("[!]: {}".format(msg))

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

def has_runtime_function(func_ea, base_address, pdata_start, pdata_end):
    """
    Check if the function has a RUNTIME_FUNCTION entry in the .pdata section.
    """
    for addr in range(pdata_start, pdata_end):
        begin_address = idc.get_wide_dword(addr)
        # debug_print("*** begin_address =  {}".format(hex(begin_address)))
        # debug_print("*** func_ea =  {}".format(hex(func_ea)))
        
        if func_ea == begin_address + base_address:
            return True
    return False
# ------------------------------------------------------------
# Calling Convention Analyzer
# ------------------------------------------------------------

def analyze_prologue(func, prologue_size):
    """
    Analyze the function prologue.

    Args:
        func (idaapi.func_t): The function object.

    Returns:
        dict: Information about the prologue.
    """
    prologue = {}
    start_ea = func.start_ea
    end_ea = start_ea + prologue_size  # Typically, the prologue is within the first few instructions

    for ea in idautils.Heads(start_ea, end_ea):
        mnem = idc.print_insn_mnem(ea)
        if mnem in ["push", "mov", "sub"]:
            prologue[ea] = idc.generate_disasm_line(ea, 0)

    return prologue


def suggest_calling_convention(unwind_info, func_start, image_base):
    return "Test"
    func = idaapi.get_func(func_start)
    
    if not func:
        debug_print("Fail")
    
    prologue = analyze_prologue(func, unwind_info["SizeOfProlog"])
    
    
# ------------------------------------------------------------
# Parsing The Unwinding Structure
# ------------------------------------------------------------

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
        # debug_print("i = {}, val = {}, at offset: {} \n".format(i, code, hex(addr)))
        if code[1] == 0:  # UWOP_PUSH_NONVOL
            reg = reg_names[code[2]]
            non_volatile_registers.append(reg)
        elif code[1] == 4 or code[1] == 5:  # UWOP_SAVE_NONVOL or UWOP_SAVE_NONVOL_FAR
            reg = reg_names[code[2]]
            non_volatile_registers.append(f"{reg} (at offset {code[0]})")
        elif code[1] == 1:  # UWOP_ALLOC_LARGE
            if code[2] == 0: # OpInfo = 0
                stack_allocation_size = 8 * ida_bytes.get_wide_word(addr + 4 + i * 2 + 2) # addr + 4 + i * 2 --> offset of the UNWIND_CODE
                unwind_codes.remove(unwind_codes[i+1])
            else:
                error_print("Large stack, opinfo 1, at offset: = {} CAN'T Parse IT!\n".format(hex(addr + 4 + i * 2)))
                stack_allocation_size += -1
                unwind_codes.remove(unwind_codes[i+1])
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

def parse_prolog(func_ea, prologue_size):
    # Iterate through instructions in the function
    for head in idautils.Heads(func_ea, func_ea + prologue_size):
        if idc.print_insn_mnem(head) == "call":
            print("\tProlog at: {} calls: {}".format(hex(func_ea), idc.print_operand(head, 0)))
            return True
        
    return False

def find_rax_value(func_ea, prologue_size):
    """
    Get the value that is loaded into a given register. Support only eax/rax:
    mov <reg>, values
    """
    for head in idautils.Heads(func_ea, func_ea + prologue_size):
        if idc.print_insn_mnem(head) == "mov" and (idc.print_operand(head, 0) == "rax" or idc.print_operand(head, 0) == "eax"):
            # debug_print("### {} {} {}".format(idc.print_insn_mnem(head), idc.print_operand(head, 0), idc.print_operand(head, 1)))
            return idc.print_operand(head, 1)
        
    return -1

def get_stack_size(func_ea, prologue_size):
    """
    Get the stack size allocated in the prolog of a function.
    """
    func = idaapi.get_func(func_ea)
    if not func:
        return None
    
    stack_size = 0
    # Iterate through instructions in the function
    for head in idautils.Heads(func_ea, func_ea + prologue_size):
        if idc.print_insn_mnem(head) == "sub" and idc.print_operand(head, 0) == "rsp":
            if idc.print_operand(head, 1) == "eax" or idc.print_operand(head, 1) == "rax":
                # print("[+] Stack allocation using register at offset: {}".format(hex(func_ea)))
                stack_size = find_rax_value(func_ea, prologue_size)
                break
            else:
                stack_size = idc.get_operand_value(head, 1)
            break
        
    return stack_size


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
            calling_convention = suggest_calling_convention(unwind_info, func_start, image_base)
            
            if get_stack_size(func_start, unwind_info["SizeOfProlog"]) == unwind_info["StackAllocationSize"]:
                is_diff_stack_size = False
            else:
                is_diff_stack_size = True
                print("[+] Stack doesn't match at offset: {}".format(hex(func_start)))
                
            if unwind_info['FrameRegister'] > 0:
                print("[+] Stack frame allocation at offset: {}".format(hex(func_start)))
                
            parse_prolog(func_start, unwind_info["SizeOfProlog"])
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
                f"Is different Stack Size? {is_diff_stack_size}\n\n"
            )

            idc.set_func_cmt(func_start, comment, 1)
            return
        
    function_without_unwind.append(hex(func_start))


def add_comments():
    """Add comments to each function based on UNWIND_INFO."""
    image_base = get_image_base()
    pdata_start, pdata_end = get_pdata_segment()
    if pdata_start is None:
        return
    
    for func_start in idautils.Functions():
        process_function(func_start, image_base, pdata_start, pdata_end)
    
    if IS_PRINT_NON_UNWIND_FUNCTION: 
        print("Funcions without stack unwinding:\n {}".format('\n'.join(function_without_unwind)))
            
print("Started stack unwinding process...")
add_comments()
print("Finished adding comments based on UNWIND_INFO.")
