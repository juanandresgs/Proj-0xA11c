import idaapi
import idc
import ida_struct
import ida_bytes

is_64bit = idaapi.get_inf_structure().is_64bit()

if is_64bit:
    print("64-bit executable detected")
    slice_struct_name = "Rust::Slice64"
    string_struct_name = "Rust::String64"
    member_flag = idaapi.FF_DWORD | idaapi.FF_QWORD
else:
    print("32-bit executable detected")
    slice_struct_name = "Rust:Slice"
    string_struct_name = "Rust:String"
    member_flag = idaapi.FF_DWORD

member_size = 8 if is_64bit else 4

def create_struct(name, members):
    # Check if the structure already exists
    sid = idc.get_struc_id(name)
    if sid != idc.BADADDR:
        print(f"Structure {name} already exists.")
        return sid
    
    # Create a new structure
    sid = idc.add_struc(-1, name, 0)
    if sid == idc.BADADDR:
        print(f"Failed to create structure {name}.")
        return idc.BADADDR
    
    # Add members to the structure
    for offset, member_name in enumerate(members):
        # print(f"offset: {offset * member_size}, {member_name}, size: {member_size}, flag: {member_flag}")
        if idc.add_struc_member(sid, member_name, offset * member_size, member_flag, -1, member_size) != 0:
            print(f"Failed to add member {member_name} to structure {member_name}, offset {offset * 4}")
        else:
            print(f"Member {member_name} added to structure {name}")
    
    print(f"Structure {name} created with ID {sid}.")
    return sid

def set_member_to_pointer(struct_name, data_member_name):
    struct_id = idc.get_struc_id(struct_name)
    struct = ida_struct.get_struc(struct_id)
    data_member = ida_struct.get_member_by_name(struct, data_member_name)
    data_tinfo = idaapi.tinfo_t()
    data_tinfo.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID))
    if idaapi.set_member_tinfo(struct, data_member, 0, data_tinfo, idaapi.SET_MEMTI_COMPATIBLE) == idaapi.SMT_OK:
        print(f"Member type for {data_member_name} set to char*")
    else:
        print(f"Failed to set member type for {data_member_name}")
    
members = [
    "content",  # Integer
    "length"   # Pointer
]
# struct_name = "Rust::Slice"
create_struct(slice_struct_name, members)
set_member_to_pointer(slice_struct_name, "content")

members = [
    "capacity",  # Integer
    "content",  # Integer
    "length"   # Pointer
]
# struct_name = "Rust::Slice"
create_struct(string_struct_name, members)
set_member_to_pointer(string_struct_name, "content")
