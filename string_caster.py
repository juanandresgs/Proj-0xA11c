import idaapi
idaapi.require("FeatureProof.FeatureProof")
from FeatureProof.FeatureProof import *

# Check bitness and set the correct structs based on that
required_structs = []
slice_struct = ""
string_struct = ""
if is_64bit():
    required_structs = ["rust__Slice64", "rust__String64", "rust__DebugInfo64"]
    slice_struct = "rust__Slice64"
    string_struct = "rust_String64"
    debug_struct = "rust__DebugInfo64"
else:
    required_structs = ["rust__Slice", "rust__String", "rust__DebugInfo"]
    slice_struct = "rust__Slice"
    string_struct = "rust_String"
    debug_struct = "rust__DebugInfo"

# Check structs have been defined
for struct in required_structs:
    if does_struct_exist(struct):
        print(f"Flight Check: Struct Exists {struct}") # DEBUG
    else:
        raise Exception("Error: Can't proceed without adding {struct}")
        
# Create a list of all strings
list_of_strings = get_all_strings()

rdata_strings_w_code_refs = []
rdata_strings_w_rdata_refs = []
rdata_xmmword_w_code_refs = []
# Check XREFs for all of those strings
for addr, content in list_of_strings:
    str_segm = get_segment_name_at_address(format_ea_t(addr))
    if "rdata" in str_segm:
        xrefs = get_all_xref_addresses_to_this_address(format_ea_t(addr))
        if xrefs:
            # print(f"{str_segm}:{addr} is {content}") #DEBUG
            for x in xrefs:
                x_segm = get_segment_name_at_address(format_ea_t(x))
                # print(f"{x_segm}:{x}:") # DEBUG
                if "text" in x_segm:
                    rdata_strings_w_code_refs.append((str_segm,addr,content,x_segm,x))
                elif "rdata" in x_segm:
                    rdata_strings_w_rdata_refs.append((str_segm,addr,content,x_segm,x))
                else:
                    print(f"Unhandled xref case: {str_segm}:{addr} -> {x_segm}:{x} :: {content}") # DEBUG
# print(f"rdata_strings_w_code_refs: {rdata_strings_w_code_refs}") #DEBUG
# print(f"rdata_strings_w_rdata_refs: {rdata_strings_w_rdata_refs}") #DEBUG

# TODO: YOU'RE MISSING ALL THE XMMWORD STUFF
# Look for XMMs in rdata w XREFs from text? DOESN'T WORK
# Can't walk to find them, need to come from the CODE side

# Check rdata refs for defined struct types
for str_segm, str_addr, str_content, xref_segm, xref_addr in rdata_strings_w_rdata_refs:
    # print(f"{str_segm}:{str_addr}, {str_content} {xref_segm}:{xref_addr}") #DEBUG
    # Check for Path Structs set by panic_attack.py
    xref_type = get_symbol_type(format_ea_t(xref_addr))
    if not xref_type:
        # print(f"{xref_addr} has no type. Check for unidentified edgecase.") # DEBUG
        continue
    elif "rust__DebugInfo" in xref_type:
        continue
    else:
        if str_content.endswith(".rs") and ('\\' in str_content or '/' in str_content):
            # NOTE: panic_attack is missing some cases, type isn't being set properly, shown by this.
            # print(f"proj-0xA11C>> If {str_addr} ({str_content}) is a path, you should consider running panic_attack.py first. {xref_addr} type is {xref_type}") # DEBUG
            continue
    if set_symbol_type_to_custom_struct(format_ea_t(xref_addr), slice_struct):
        print(f"Changed to slice: {xref_segm}:{xref_addr}:{xref_type}->{get_symbol_type(format_ea_t(xref_addr))}")
        # TODO: Double check all of the string lengths based on these structs
        rename_symbol_at_address(format_ea_t(xref_addr),("rsli_" + sanitize_ida_symbol_name(str_content[:30])))

# TODO: NEED TO HANDLE DUPLICATE NAMES

# for str_segm, str_addr, str_content, xref_segm, xref_addr in rdata_strings_w_code_refs:
#     print(f"{str_segm}:{str_addr}, {str_content} {xref_segm}:{xref_addr}") #DEBUG
# NOTE: Can fine functions not currently defined, based on strings w CODE references.
# TODO: HOW DO WE HANDLE THESE??

# TODO: WHAT ABOUT STRUCTS THAT SHOULD BE SET INTO THE FUNCTIONS?

# How do we divide which ones are slices/strings
# How do we handle which ones have XMMWORD loads?
# How do we handle strings w no XREFs that are dummy copies of strings loaded in the code?
# Apply the appropriate struct
# Use the struct to double check the string
# Rename the symbol of the struct

# What are we missing?
# What benefit did this bring to the decompilation?
