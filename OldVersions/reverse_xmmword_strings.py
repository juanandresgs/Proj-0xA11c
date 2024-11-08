from idaapi import *
from idc import *
from idautils import *

def reverse_xmmword(data):
    # Reverse the byte order of a given 16-byte xmmword
    reversed_data = data[::-1]
    return reversed_data

def is_printable_string(data):
    # Check if the data contains printable ASCII characters
    return all(32 <= byte <= 126 for byte in data)

def process_xmmword(ea):
    # Read 16 bytes from the address
    data = get_bytes(ea, 16)
    if data is None:
        return
    
    if is_printable_string(data):
        reversed_data = reverse_xmmword(data)
        # Create a string from reversed bytes for display
        reversed_string = ''.join(chr(b) for b in reversed_data)
        # Update the database with the reversed string
        del_items(ea, 16, DELIT_SIMPLE)
        create_strlit(ea, ea + 16)
        patch_bytes(ea, reversed_data)
        print(f"Updated xmmword at {ea:x}: {reversed_string}")

# Get the .rdata section
rdata_seg = get_segm_by_name(".rdata")
if not rdata_seg:
    print(".rdata section not found")    
else:
    ea = rdata_seg.start_ea
    end_ea = rdata_seg.end_ea
    while ea < end_ea:
        if get_item_size(ea) == 16:  # Check if item is xmmword (16 bytes)
            process_xmmword(ea)
        ea = next_head(ea, end_ea)


