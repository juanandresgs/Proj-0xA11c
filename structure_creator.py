import idaapi
import idc
import ida_struct
import ida_bytes
import re
import os

is_64bit = idaapi.get_inf_structure().is_64bit()

if is_64bit:
    print("64-bit executable detected")
    member_flag = idaapi.FF_DWORD | idaapi.FF_QWORD
else:
    print("32-bit executable detected")
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
    for offset, (member_name, member_type) in enumerate(members):
        # print(f"offset: {offset * member_size}, {member_name}, size: {member_size}, flag: {member_flag}")
        if idc.add_struc_member(sid, member_name, offset * member_size, member_flag, -1, member_size) != 0:
            print(f"Failed to add member {member_name} to structure {name}, offset {offset * member_size}")
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

def parse_structure_pack(file_path):
    if not os.path.isfile(file_path):
        print(f"File {file_path} not found.")
        return
    
    with open(file_path, 'r') as f:
        content = f.read()

    struct_pattern = re.compile(r"struct\s+(\w+)\s*{([^}]*)};")
    members_pattern = re.compile(r"\s*(\w+)\s+(\w+);")

    for struct_match in struct_pattern.finditer(content):
        struct_name = struct_match.group(1)
        members_block = struct_match.group(2)
        members = []
        for member_match in members_pattern.finditer(members_block):
            member_type = member_match.group(1)
            member_name = member_match.group(2)
            members.append((member_name, member_type))
        
        create_struct(struct_name, members)
        # Assuming the first member needs to be set to pointer for demonstration
        if members:
            set_member_to_pointer(struct_name, members[0][0])

# Main logic
# Provide the full path to structure_pack.h
parse_structure_pack(os.path.join(os.path.dirname(__file__), 'structure_pack.h'))
