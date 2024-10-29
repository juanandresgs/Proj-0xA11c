import idaapi
import logging
idaapi.require("FeatureProof")
from FeatureProof.FeatureProof import Middleware
from FeatureProof.TypeInfo import *

fp = Middleware()
fp.set_logging_level(level=logging.INFO)
logger = fp.logger

# Set bitness specific constants
if fp.is_64bit():
    logger.info("64-bit executable detected")
    slice_struct_name = "Rust_Slice64"
    string_struct_name = "Rust_String64"
else:
    logger.info("32-bit executable detected")
    slice_struct_name = "Rust_Slice"
    string_struct_name = "Rust_String"


'''
    https://hex-rays.com/products/ida/support/idadoc/276.shtml
'''
def check_around(head):
    '''
    Check the instruction before and after the area where we suspect our String is at
    '''
    # If the is an instruction that sets an integer to the stack - it's not a string
    logger.debug(f"Checking instruction at {hex(head), fp.get_operand_type(head, 0), fp.get_operand_type(head, 1)}")

    prev_head = fp.get_previous_instruction_address(head)
    logger.debug(f"Checking instruction at {hex(prev_head), fp.get_operand_type(prev_head, 0), fp.get_operand_type(prev_head, 1)}")

    prev_prev_head = fp.get_previous_instruction_address(prev_head)
    logger.debug(f"Checking instruction at {hex(prev_prev_head), fp.get_operand_type(prev_prev_head, 0), fp.get_operand_type(prev_prev_head, 1)}")


    if fp.get_operand_type(prev_prev_head, 0) == TYPE_DISPLACEMENT and fp.get_operand_type(prev_prev_head, 1) == TYPE_REGISTER:
       return False
    return True

def find_strings_in_code(start_ea, end_ea):
    '''
    A String is where an integer, a pointer to a string, and another integer are all pushed to the stack in that order.
    To reduce false-postive we need to look a few instructions before and after the potential String location
    '''
    stack_operations = []

    # Find potential String places
    for head in idautils.Heads(start_ea, end_ea):
        if fp.get_instruction(head) == "mov":
            op1 = fp.get_operand_value(head, 0) # DEBUG: Why are we doing this? Value not used.
            op2 = fp.get_operand_value(head, 1) # DEBUG: Why are we doing this? Value not used.
            # INCOMPLETE CODE???

            # Check for stack operation saving an integer
            # o_displ(4) Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
            if fp.get_operand_type(head, 0) == TYPE_DISPLACEMENT and fp.get_operand_type(head, 1) == TYPE_IMMEDIATE:
                if fp.get_operand_value(head, 1) > 0:
                    next_head = fp.get_next_instruction_address(head, end_ea)
                    # Check for register holding a pointer to a string ***
                    if TYPE_DISPLACEMENT and fp.get_operand_type(next_head, 1) == TYPE_REGISTER:
                        next_next_head = fp.get_next_instruction_address(next_head, end_ea)
                        # Check for another stack operation saving an integer
                        if fp.get_operand_type(next_next_head, 0) == TYPE_DISPLACEMENT and fp.get_operand_type(next_next_head, 1) == TYPE_IMMEDIATE:
                            # check
                            if check_around(head):
                                stack_operations.append((head))
                                logger.debug(f"String at: {hex(head)}")

    return stack_operations

def get_string_length(addr):
    """Get the length of the string at the given address."""
    string_content = idc.get_strlit_contents(addr, -1, idc.STRTYPE_C)
    if string_content:
        return len(string_content.decode('utf-8'))
    return 0

def find_slices_in_rdata():
    """Find places in .rdata where a pointer to a string is followed by its length."""
    results = []
    seg = ida_segment.get_segm_by_name(".rdata") # TODO: Convert to FP function
    if not seg:
        logger.debug("[-] .rdata segment not found.")
        return

    ea = seg.start_ea
    end_ea = seg.end_ea

    while ea < end_ea:
        if idc.is_code(idc.get_full_flags(ea)):
            ea = fp.get_next_instruction_address(ea, end_ea)
            continue

        ptr_value = fp.get_qword_at_address(ea)
        if idc.is_loaded(ptr_value) and idc.is_strlit(ida_bytes.get_full_flags(ptr_value)):
            #logger.debug("Found a slice --> offset:{}, content: {}, length: {}".format(hex(ea), idc.get_strlit_contents(ptr_value, -1, idc.STRTYPE_C), hex(next_qword)))
            results.append(ea)
        if fp.is_64bit():
            next_qword = fp.get_qword_at_address(ea += 8)
        else:
            next_qword = fp.get_dword_at_address(ea += 4)

    return results

def is_string(addr):
    """Check if the address contains a string."""
    return idc.is_strlit(ida_bytes.get_full_flags(addr))

def is_in_rdata(addr):
    """Check if the address is in the .rdata section or any read-only data section."""
    seg = ida_segment.getseg(addr)
    if seg and (seg.perm & ida_segment.SEGPERM_READ):
        seg_name = ida_segment.get_segm_name(seg) #TODO: Convert to FP function
        return seg_name == '.rdata' or seg_name.startswith('.rodata')
    return False

def find_slices_in_code(start_ea, end_ea):
    """Find instructions that load a string and its length into the stack.
    Searching in the .text area

    Find:
        lea     rax, aSlice       ; "slice"
        mov     [rsp+0D8h+var_30], rax
        mov     [rsp+0D8h+var_28], 5

    Exclude:

        mov     edx, eax
        mov     dword ptr [ecx+18h], offset aInvalidDistanc_1 ; "invalid distance too far back"
        mov     dword ptr [eax+4], 3F51h


    #define o_void        0  // No Operand                           ----------
    #define o_reg         1  // General Register (al, ax, es, ds...) reg
    #define o_mem         2  // Direct Memory Reference  (DATA)      addr
    #define o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
    #define o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    """
    results = []

    ea = start_ea
    while ea < end_ea:
        mnem = fp.get_instruction(ea)

        # Check for lea or mov instruction (loading the address of a string)
        if mnem in ["lea"]:
            reg = idc.print_operand(ea,0) #TODO: Convert to FP function.
            if fp.get_operand_type(ea, 0) == TYPE_REGISTER and fp.get_operand_type(ea, 1) == TYPE_MEM and "sub" not in idc.print_operand(ea, 1) and "stru" not in idc.print_operand(ea, 1):
                # str_length = get_string_length(opnd1)

                # Check the next instructions for the string address and length being pushed onto the stack
                # ToDo - define a slice only when the number that is pushed in the second instruction is within one offset from the offset to which the pointer was pushed: rsp+0D8h+var_30 and rsp+0D8h+var_28
                next_ea = fp.get_next_instruction_address(ea, end_ea)
                if fp.get_instruction(next_ea) == "mov" and "[" in idc.print_operand(next_ea, 0) and fp.get_operand_type(next_ea, 1) == TYPE_REGISTER and reg == idc.print_operand(next_ea,1):
                    next_next_ea = fp.get_next_instruction_address(next_ea, end_ea)
                    if fp.get_operand_type(next_next_ea, 0) == TYPE_DISPLACEMENT and fp.get_operand_type(next_next_ea, 1) == TYPE_IMMEDIATE:
                        print(hex(next_next_ea))
                        print(f"{idc.print_operand(next_next_ea, 1)}")

                        if fp.get_operand_value(next_next_ea, 1) > 0:
                            results.append(ea)
        ea = fp.get_next_instruction_address(ea, end_ea)
    return results

# doesn't work
def apply_structure(ea, sid, struct_name):
    """Apply the structure at the given address."""
    struct_size = ida_struct.get_struc_size(sid) #TODO: Convert to FP function.

    # Apply the structure to the address
    if ida_bytes.create_struct(ea, struct_size, sid): #TODO: Convert to FP function.
        logger.debug(f"Successfully applied '{struct_name}' to address 0x{ea:X}.")
        return True
    else:
        logger.error(f"Failed to apply '{struct_name}' to address 0x{ea:X}.")

    return False


slice_sid = idc.get_struc_id(slice_struct_name) #TODO: Convert to FP function.
if slice_sid == BADADDR: #TODO: Set a type for BADADDR
    logger.error(f"Structure '{slice_struct_name}' doesn't exists! Run the script 'define_string_structs.py' first.")

else:
    # Look for slices in the .rdata section
    logger.info("Looking for slices in the .rdata segment...")
    results = find_slices_in_rdata()
    if results:
        for ea in results:
            logger.debug(f"Found slice pointer with length at: 0x{ea:X} in .rdata.")
            apply_structure(ea, slice_sid, slice_struct_name)

    logger.info("Looking for slices in the .text segment...")
    # Look for slices in the .text section
    for func_start in idautils.Functions():
        func_end = idc.find_func_end(func_start) #TODO: Convert to FP function.
        results = find_slices_in_code(func_start, func_end)
        for ea in results:
            logger.debug(f"Found slice pointer with length at: 0x{ea:X} in .text.")
            # apply_structure(ea, slice_sid, slice_struct_name)
            # DEBUG: Why is this commented out?


string_sid = idc.get_struc_id(string_struct_name) #TODO: Convert to FP function.
if slice_sid == BADADDR:
    logger.error(f"Structure '{string_struct_name}' doesn't exists! Run the script 'define_string_structs.py' first.")

else:
    logger.info("Looking for strings in the .text segment...")

    for func_start in idautils.Functions(): #TODO: Convert to FP function.
        func_end = idc.find_func_end(func_start) #TODO: Convert to FP function.
        results = find_strings_in_code(func_start, func_end)
        for ea in results:
            logger.debug(f"Found string pointer with length at: 0x{ea:X} in .text.")
            # apply_structure(ea, slice_sid, slice_struct_name)
            # DEBUG: Why is this commented out?
