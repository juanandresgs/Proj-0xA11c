import idaapi
import idc
import ida_struct
import ida_bytes
import ida_segment
import ida_kernwin
import idautils


# Determine the bitness of the binary
is_64bit = idaapi.get_inf_structure().is_64bit()
if is_64bit:
    print("64-bit executable detected")
    slice_struct_name = "rust__Slice64"
    string_struct_name = "rust__String64"
else:
    print("32-bit executable detected")
    slice_struct_name = "rust__Slice"
    string_struct_name = "rust__String"
        
'''
https://hex-rays.com/products/ida/support/idadoc/276.shtml
'''
def check_around(head):
    '''
    Check the instruction before and after the area where we suspect our String is at
    '''
    # If the is an instruction that sets an integer to the stack - it's not a string
    # print(hex(head), idc.get_operand_type(head, 0), idc.get_operand_type(head, 1))
    prev_head = idc.prev_head(head)
    # print(hex(prev_head), idc.get_operand_type(prev_head, 0), idc.get_operand_type(prev_head, 1))
    
    prev_prev_head = idc.prev_head(prev_head)
    # print(hex(prev_prev_head), idc.get_operand_type(prev_prev_head, 0), idc.get_operand_type(prev_prev_head, 1))
    
    
    if idc.get_operand_type(prev_prev_head, 0) == idc.o_displ and idc.get_operand_type(prev_prev_head, 1) == idc.o_reg:
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
        if idc.print_insn_mnem(head) == "mov":
            op1 = idc.get_operand_value(head, 0)
            op2 = idc.get_operand_value(head, 1)

            # Check for stack operation saving an integer
            # o_displ(4) Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
            if idc.get_operand_type(head, 0) == idc.o_displ and idc.get_operand_type(head, 1) == idc.o_imm:
                if idc.get_operand_value(head, 1) > 0:
                    next_head = idc.next_head(head, end_ea)
                    # Check for register holding a pointer to a string ***
                    if idc.o_displ and idc.get_operand_type(next_head, 1) == idc.o_reg:
                        next_next_head = idc.next_head(next_head, end_ea)
                        # Check for another stack operation saving an integer
                        if idc.get_operand_type(next_next_head, 0) == idc.o_displ and idc.get_operand_type(next_next_head, 1) == idc.o_imm:
                            # check
                            if check_around(head):
                                stack_operations.append((head))
                                # print("String at: {}".format(hex(head)))

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
    seg = ida_segment.get_segm_by_name(".rdata")
    if not seg:
        print("[-] .rdata segment not found.")
        return

    ea = seg.start_ea
    end_ea = seg.end_ea

    while ea < end_ea:
        if idc.is_code(idc.get_full_flags(ea)):
            ea = idc.next_head(ea, end_ea)
            continue
        
        ptr_value = idc.get_qword(ea)
        if idc.is_loaded(ptr_value) and idc.is_strlit(ida_bytes.get_full_flags(ptr_value)):
            if is_64bit:
                next_qword = idc.get_qword(ea + 8)
            else:
                next_qword = idc.get_wide_dword(ea + 4)
            # print("Found a slice --> offset:{}, content: {}, length: {}".format(hex(ea), idc.get_strlit_contents(ptr_value, -1, idc.STRTYPE_C), hex(next_qword)))     
            results.append(ea)
        if is_64bit:
            ea += 8
        else:
            ea += 4

    return results

def is_string(addr):
    """Check if the address contains a string."""
    return idc.is_strlit(ida_bytes.get_full_flags(addr))

def is_in_rdata(addr):
    """Check if the address is in the .rdata section or any read-only data section."""
    seg = ida_segment.getseg(addr)
    if seg and (seg.perm & ida_segment.SEGPERM_READ):
        seg_name = ida_segment.get_segm_name(seg)
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
        mnem = idc.print_insn_mnem(ea)
        
        # Check for lea or mov instruction (loading the address of a string)
        if mnem in ["lea"]:
            reg = idc.print_operand(ea,0)
            if idc.get_operand_type(ea, 0) == idc.o_reg and idc.get_operand_type(ea, 1) == idc.o_mem and "sub" not in idc.print_operand(ea, 1) and "stru" not in idc.print_operand(ea, 1):
                # str_length = get_string_length(opnd1)

                # Check the next instructions for the string address and length being pushed onto the stack
                # ToDo - define a slice only when the number that is pushed in the second instruction is within one offset from the offset to which the pointer was pushed: rsp+0D8h+var_30 and rsp+0D8h+var_28
                next_ea = idc.next_head(ea, end_ea)
                if idc.print_insn_mnem(next_ea) == "mov" and "[" in idc.print_operand(next_ea, 0) and idc.get_operand_type(next_ea, 1) == idc.o_reg and reg == idc.print_operand(next_ea,1):
                    next_next_ea = idc.next_head(next_ea, end_ea)
                    if idc.get_operand_type(next_next_ea, 0) == idc.o_displ and idc.get_operand_type(next_next_ea, 1) == idc.o_imm:
                        print(hex(next_next_ea))
                        print(f"{idc.print_operand(next_next_ea, 1)}")
                    
                        if idc.get_operand_value(next_next_ea, 1) > 0:
                            results.append(ea)
        ea = idc.next_head(ea, end_ea)
    return results

# doesn't work
def apply_structure(ea, sid, struct_name):
    """Apply the structure at the given address."""
    struct_size = ida_struct.get_struc_size(sid)

    # Apply the structure to the address
    if ida_bytes.create_struct(ea, struct_size, sid):
        # print(f"Successfully applied '{struct_name}' to address 0x{ea:X}.")
        return True
    else:
        print(f"[-] Failed to apply structure '{struct_name}' to address 0x{ea:X}.")
    
    return False


slice_sid = idc.get_struc_id(slice_struct_name)
if slice_sid == idc.BADADDR:
    print(f"Structure doesn't exists!\n Run the script 'define_string_structs.py' first")

else:
    # Look for slices in the .rdata section
    print("Looking for slices in the .rdata segment...")
    results = find_slices_in_rdata()
    if results:
        for ea in results:
            print(f"Found slice pointer with length at: {hex(ea)} in .rdata")
            apply_structure(ea, slice_sid, slice_struct_name)

    print("Looking for slices in the .text segment...")
    # Look for slices in the .text section
    for func_start in idautils.Functions():
        func_end = idc.find_func_end(func_start)
        results = find_slices_in_code(func_start, func_end)
        for ea in results:
            print(f"Found slice pointer with length at: {hex(ea)} in .text")
            # apply_structure(ea, slice_sid, slice_struct_name)

    
string_sid = idc.get_struc_id(string_struct_name)
if slice_sid == idc.BADADDR:
    print(f"Structure doesn't exists!\n Run the script 'define_string_structs.py' first")

else:
    print("Looking gor strings in the .text segment...")
    
    for func_start in idautils.Functions():
        func_end = idc.find_func_end(func_start)
        results = find_strings_in_code(func_start, func_end)
        for ea in results:
            print(f"Found slice pointer with length at: {hex(ea)} in .text")
            # apply_structure(ea, slice_sid, slice_struct_name)
