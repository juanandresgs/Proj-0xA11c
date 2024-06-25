import idaapi
import idc
import ida_struct
import ida_bytes
import ida_segment
import ida_kernwin
import idautils

IS_STRING_FINDER = False

# Determine the bitness of the binary
is_64bit = idaapi.get_inf_structure().is_64bit()
if is_64bit:
    print("64-bit executable detected")
    slice_struct_name = "Rust::Slice64"
    string_struct_name = "Rust::String64"
else:
    print("32-bit executable detected")
    slice_struct_name = "Rust:Slice"
    string_struct_name = "Rust:String"
        
    
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
            print("Found a slice --> offset:{}, content: {}, length: {}".format(hex(ea), idc.get_strlit_contents(ptr_value, -1, idc.STRTYPE_C), hex(next_qword)))     
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
    """
    results = []
    
    ea = start_ea
    while ea < end_ea:
        mnem = idc.print_insn_mnem(ea)
        
        # Check for lea or mov instruction (loading the address of a string)
        if mnem in ["lea", "mov"]:
            opnd1 = idc.get_operand_value(ea, 1)
            if is_in_rdata(opnd1) and is_string(opnd1):
                # str_length = get_string_length(opnd1)

                # Check the next instructions for the string address and length being pushed onto the stack
                next_ea = idc.next_head(ea, end_ea)
                if idc.print_insn_mnem(next_ea) == "mov" and "[rsp" in idc.print_operand(next_ea, 0):
                    next_next_ea = idc.next_head(next_ea, end_ea)
                    if idc.print_insn_mnem(next_next_ea) == "mov" and "[rsp" in idc.print_operand(next_next_ea, 0):
                        int_value = idc.get_operand_value(next_next_ea, 1)
                        # print("Found a slice --> content: {} length: {} offset: {}".format(
                            # idc.get_strlit_contents(opnd1, int_value, idc.STRTYPE_C), int_value, hex(ea)))
                        # results.append((ea, next_ea, next_next_ea))
                        results.append(next_ea)
        ea = idc.next_head(ea, end_ea)
    return results

def apply_structure(ea, sid, struct_name):
    """Apply the structure at the given address."""
    # todo - change it to get the id based on the name or the otehr way around (ida_struct.get_struc_id("Rust::Slice64"))
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
    #Look for slices in the .rdata section
    print("Looking for slices in the rdata segment...")
    results = find_slices_in_rdata()
    if results:
        for ea in results:
            # print(f"Found slice at: {hex(ea)}")
            apply_structure(ea, slice_sid, slice_struct_name)

slice_sid = idc.get_struc_id(string_struct_name)
if slice_sid == idc.BADADDR:
    print(f"Structure doesn't exists!\n Run the script 'define_string_structs.py' first")
# for func_start in idautils.Functions():
#     func_end = idc.find_func_end(func_start)
#     results = find_slices_in_code(func_start, func_end)
#     for ea in results:
#         print(f"Found string pointer with length at: {hex(ea)}")
#         apply_structure(ea, slice_sid, slice_struct_name)
    
# Test
# results = find_slices_in_code(5368714784, 5368715747)
# for ea in results:
#     print(f"Found sslice at: {hex(ea)}")
#     apply_structure(ea, slice_sid, slice_struct_name)
    
    