import idaapi
import os
idaapi.require("FeatureProof.FeatureProof")
from FeatureProof.FeatureProof import Middleware

fp = Middleware()
fp.set_logging_level(level=logging.INFO)
logger = fp.logger

############ Path Handler ############
# Version 0.6                      #
######################################
# NOTE: Where the symbol is a constant, the type isn't being applied properly.



def get_struct_values(ea):
    """
    Retrieve the content of the string, line number, and column number from the struct at the given address.

    :param ea: The address of the struct.
    :param is_64bit: Boolean indicating if the structure is 64-bit.
    :return: A tuple with the string content, line number, and column number.
    """
    try:
        is64bit = is_64bit()

        # Determine offsets based on the bitness of the structure
        string_ptr_offset = 0x0
        string_len_offset = 0x8 if is64bit else 0x4
        line_number_offset = 0x10 if is64bit else 0x8
        column_number_offset = 0x14 if is64bit else 0xC

        # Read the pointer value for the string content
        string_ptr = ida_bytes.get_qword(ea + string_ptr_offset) if is64bit else ida_bytes.get_dword(ea + string_ptr_offset)
        if string_ptr == idaapi.BADADDR:
            print(f"Failed to read the pointer at address {hex(ea + string_ptr_offset)}.")
            return None, None, None

        # Read the length of the string
        string_len = ida_bytes.get_qword(ea + string_len_offset) if is64bit else ida_bytes.get_dword(ea + string_len_offset)

        # Retrieve the actual string content using the pointer and length
        string_content = idc.get_strlit_contents(string_ptr, string_len, idc.STRTYPE_C)
        if string_content:
            string_content = string_content.decode('utf-8')  # Decode bytes to string
        else:
            print(f"Failed to retrieve string content from pointer {hex(string_ptr)}.")
            string_content = None

        # Read the line number
        line_number = ida_bytes.get_dword(ea + line_number_offset)

        # Read the column number
        column_number = ida_bytes.get_dword(ea + column_number_offset)

        return string_content, line_number, column_number
    except Exception as e:
        print(f"An error occurred: {e}")
        return None, None, None

def combine_path_to_symbol_name(file_path, line_number, column_number):
    """
    Create an IDA Pro symbol name from the filename, line number, and column number.
    :param file_path: The full file path.
    :param line_number: The line number.
    :param column_number: The column number.
    :return: The sanitized IDA Pro symbol name.
    """
    try:
        # Extract the filename from the file path
        filename = os.path.basename(file_path)

        # Create the symbol name by combining the filename, line number, and column number
        symbol_name = f"{filename}_{line_number}_{column_number}"

        # Sanitize the symbol name for IDA Pro
        sanitized_symbol_name = sanitize_ida_symbol_name(symbol_name)

        return sanitized_symbol_name
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def create_formatted_comment(string_content, line_number, column_number):
    """
    Create a formatted comment string from the given string content, line number, and column number.

    :param string_content: The content of the string.
    :param line_number: The line number.
    :param column_number: The column number.
    :return: A formatted comment string.
    """
    try:
        # Format the comment
        comment = f"File: {string_content}, Line: {line_number}, Column: {column_number}"
        return comment
    except Exception as e:
        print(f"An error occurred while creating the comment: {e}")
        return None

#######################################
#GOAL:Make sure structure is added
#######################################
debug_struct = ""
slice_struct = ""
if is_64bit:
    if not does_struct_exist("rust__DebugInfo64"):
        raise Exception("Error: Can't proceed without adding rust__DebugInfo64 structure")
    else:
        debug_struct = "rust__DebugInfo64"
    if not does_struct_exist("rust__Slice64"):
        raise Exception("Error: Can't proceed without adding rust__Slice64 structure")
    else:
        slice_struct = "rust__Slice64"
else:
    if not does_struct_exist("rust__DebugInfo"):
        raise Exception("Error: Can't proceed without adding rust__DebugInfo structure")
    else:
        debug_struct = "rust__DebugInfo"
    if not does_struct_exist("rust__Slice"):
        raise Exception("Error: Can't proceed without adding rust__Slice structure")
    else:
        slice_struct = "rust__Slice"

#######################################
#GOAL:Find Path Strings
#######################################
paths = set()
for s in get_strings_ending_with(".rs"):
    if '\\' in s[1] or '/' in s[1]:
        paths.add(s)

#LOGIC:Well what's the next heuristic? That it has XREFs in its own segment that can fit into our debugInfo struct?

#######################################
#GOAL:Rename the path symbol
#######################################

#TODO: ADD LOGIC TO HANDLE DUPLICATE SYMBOL NAMES
for s in paths:
    address = s[0]
    sanitized_name = "Path_" + sanitize_ida_symbol_name(s[1])
    rename_symbol_at_address(format_ea_t(address), sanitized_name)

#######################################
#GOAL:Get all XREFs
#######################################

for addr, symbol in paths:
    addr = format_ea_t(addr)
    path_segment = get_segment_name_at_address(addr)
    name = "rdi_" + sanitize_ida_symbol_name(symbol)
    xrefs = get_all_xref_addresses_to_this_address(addr)
    # print(name) # DEBUG
    for x in xrefs:
        if get_segment_name_at_address(format_ea_t(x)) == path_segment:
            # print(f"Suspected Path struct at: ", x) # DEBUG
            formatted_x = format_ea_t(x)
            set_symbol_type_to_custom_struct(formatted_x, debug_struct)
            string_content, line_number, column_number = get_struct_values(formatted_x)
            combined_name = combine_path_to_symbol_name(string_content, line_number, column_number)
            rename_symbol_at_address(formatted_x, combined_name)
            better_comment = create_formatted_comment(string_content, line_number, column_number)
            set_comment_at_address(formatted_x, better_comment, True)
            for xref in get_all_xref_addresses_to_this_address(formatted_x):
                set_comment_at_address(format_ea_t(xref), better_comment, True)



###########################################
# Gains start here
###########################################
#-> What does this do for us at the decomp level?
#-> What does it tell us about the function from which it’s being referenced?
#-> What should we do with that information?
#	- Add comment?
#   - Rename function?
# 	- Move function to folder?
############################################
