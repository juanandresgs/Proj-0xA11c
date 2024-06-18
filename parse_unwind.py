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

def parse_c_scope_table(scope_table_addr, num_entries):
    """Parse the C_SCOPE_TABLE structure."""
    scopes = []
    entry_size = 2 * 4  # Each entry is two 4-byte values (start and end RVA)

    for i in range(num_entries):
        start_rva = idc.get_wide_dword(scope_table_addr + i * entry_size)
        end_rva = idc.get_wide_dword(scope_table_addr + i * entry_size + 4)
        scopes.append((start_rva, end_rva))
        debug_print(f"C_SCOPE_TABLE Entry {i}: start=0x{start_rva:X}, end=0x{end_rva:X}")

    return scopes

def parse_unwind_info(unwind_info_addr, image_base):
    """Parse the UNWIND_INFO structure."""
    debug_print(f"Parsing UNWIND_INFO at address: 0x{unwind_info_addr:X}")
    unwind_info = idaapi.get_bytes(unwind_info_addr, 4)
    if not unwind_info or len(unwind_info) < 4:
        # debug_print("Invalid UNWIND_INFO structure")
        return None

    version_flags = unwind_info[0]
    version = version_flags & 0xF
    flags = (version_flags >> 4) & 0xF
    prolog_size = unwind_info[1]
    num_codes = unwind_info[2]
    frame_register = (unwind_info[3] >> 4) & 0xF
    frame_offset = unwind_info[3] & 0xF

    debug_print(f"Version: {version}, Flags: {flags}, Prolog Size: {prolog_size}, Number of Codes: {num_codes}, Frame Register: {frame_register}, Frame Offset: {frame_offset}")

    unwind_codes = idaapi.get_bytes(unwind_info_addr + 4, num_codes * 2)
    if not unwind_codes:
        debug_print("No UNWIND_CODE data found")
        return {
            "stack_alloc_size": 0,
            "frame_register": frame_register,
            "nonvolatile_registers": [],
            "handler_addr": None,
            "scopes": []
        }

    code_idx = 0
    stack_alloc_size = 0
    nonvolatile_registers = []

    while code_idx < len(unwind_codes):
        code_offset = unwind_codes[code_idx]
        unwind_op = unwind_codes[code_idx + 1] & 0xF
        op_info = (unwind_codes[code_idx + 1] >> 4) & 0xF

        if unwind_op == 0:  # UWOP_PUSH_NONVOL
            nonvolatile_registers.append(op_info)
        elif unwind_op == 1:  # UWOP_ALLOC_LARGE
            if op_info == 0:
                stack_alloc_size = int.from_bytes(unwind_codes[code_idx + 2:code_idx + 4], 'little')
                code_idx += 2
            elif op_info == 1:
                stack_alloc_size = int.from_bytes(unwind_codes[code_idx + 2:code_idx + 6], 'little')
                code_idx += 4
        elif unwind_op == 2:  # UWOP_ALLOC_SMALL
            stack_alloc_size = (op_info * 8) + 8
        elif unwind_op == 3:  # UWOP_SET_FPREG
            frame_register = op_info
            frame_offset = code_offset

        code_idx += 2

    handler_addr = None
    scopes = []
    if flags & 1:  # UNW_FLAG_EHANDLER
        handler_addr = idc.get_wide_dword(unwind_info_addr + 4 + num_codes * 2) + image_base
        num_entries = idc.get_wide_dword(unwind_info_addr + 4 + num_codes * 2 + 4)
        scope_table_addr = unwind_info_addr + 4 + num_codes * 2 + 8
        # scopes = parse_c_scope_table(scope_table_addr, num_entries)
        scopes = ""
        debug_print(f"scope_table_addr: 0x{scope_table_addr:X}, num_entries:{num_entries}\n")

    debug_print(f"Stack Allocation Size: {stack_alloc_size}, Nonvolatile Registers: {nonvolatile_registers}, Exception Handler Address: {handler_addr}, Scopes: {scopes}")

    return {
        "stack_alloc_size": stack_alloc_size,
        "frame_register": frame_register,
        "nonvolatile_registers": nonvolatile_registers,
        "handler_addr": handler_addr,
        "scopes": scopes
    }


def process_function(func_start, image_base, pdata_start, pdata_end):
    """Process a single function and add comments based on UNWIND_INFO."""
    for addr in range(pdata_start, pdata_end, 12):
        start_rva = idc.get_wide_dword(addr)
        end_rva = idc.get_wide_dword(addr + 4)
        # debug_print(f"Function  found: start=0x{image_base + start_rva:X}, end=0x{image_base + end_rva:X}")
        unwind_info_rva = idc.get_wide_dword(addr + 8)

        comment = "--- Stack Unwinding Information ---\n"

        if func_start == image_base + start_rva:
            unwind_info_addr = image_base + unwind_info_rva
            unwind_info = parse_unwind_info(unwind_info_addr, image_base)
            comment += "Stack Allocation Size: {} bytes\n".format(unwind_info["stack_alloc_size"])
            if unwind_info["frame_register"]:
                comment += "Frame Register: {}\n".format(idaapi.get_reg_name(unwind_info["frame_register"], 8))
            if unwind_info["nonvolatile_registers"]:
                nonvol_regs = [idaapi.get_reg_name(reg, 8) for reg in unwind_info["nonvolatile_registers"]]
                comment += "Saved Nonvolatile Registers: {}\n".format(", ".join(nonvol_regs))
            if unwind_info["handler_addr"]:
                comment += "Exception Handler Address: 0x{:X}\n".format(unwind_info["handler_addr"])
            
            comment += "\n"
            idc.set_func_cmt(func_start, comment, 0)
            debug_print(f"Added comment to function at 0x{func_start:X}")
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
