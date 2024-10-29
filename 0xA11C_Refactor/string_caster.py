import idaapi
import logging
idaapi.require("FeatureProof.FeatureProof")
from FeatureProof.FeatureProof import Middleware

fp = Middleware()
fp.set_logging_level(level=logging.INFO)
logger = fp.logger

# Check bitness and set the correct structs based on that
required_structs = []
slice_struct = ""
string_struct = ""
if fp.is_64bit():
    required_structs = ["Rust_Slice64", "Rust_String64", "Rust_DebugInfo64"]
    slice_struct = "Rust_Slice64"
    string_struct = "Rust_String64"
    debug_struct = "Rust_DebugInfo64"
else:
    required_structs = ["rust_Slice", "Rust_String", "Rust_DebugInfo"]
    slice_struct = "Rust_Slice"
    string_struct = "Rust_String"
    debug_struct = "Rust_DebugInfo"

# Check structs have been defined
for struct in required_structs:
    if fp.does_struct_exist(struct):
        logger.debug(f"Flight Check: Struct Exists {struct}")
    else:
        logger.error(f"Error: Can't proceed without adding {struct}")
        raise Exception("Error: Can't proceed without adding {struct}")

# Create a list of all strings
list_of_strings = fp.get_all_strings()

rdata_strings_w_code_refs = []
rdata_strings_w_rdata_refs = []
rdata_xmmword_w_code_refs = []
# Check XREFs for all of those strings
for addr, content in list_of_strings:
    str_segm = fp.get_segment_name_at_address(fp.format_ea_t(addr))
    if "rdata" in str_segm:
        xrefs = fp.get_all_xref_addresses_to_this_address(fp.format_ea_t(addr))
        if xrefs:
            logger.debug(f"{str_segm}:{addr} is {content}")
            for x in xrefs:
                x_segm = fp.get_segment_name_at_address(fp.format_ea_t(x))
                logger.debug(f"{str_segm}:{addr} -> {x_segm}:{x}")
                if "text" in x_segm:
                    rdata_strings_w_code_refs.append((str_segm,addr,content,x_segm,x))
                elif "rdata" in x_segm:
                    rdata_strings_w_rdata_refs.append((str_segm,addr,content,x_segm,x))
                else:
                    logger.debug(f"Unhandled xref case: {str_segm}:{addr} -> {x_segm}:{x} :: {content}")
logger.debug(f"rdata_strings_w_code_refs: {rdata_strings_w_code_refs}")
logger.debug(f"rdata_xmmword_w_code_refs: {rdata_xmmword_w_code_refs}")

# TODO: YOU'RE MISSING ALL THE XMMWORD STUFF
# Look for XMMs in rdata w XREFs from text? DOESN'T WORK
# Can't walk to find them, need to come from the CODE side

# Check rdata refs for defined struct types
for str_segm, str_addr, str_content, xref_segm, xref_addr in rdata_strings_w_rdata_refs:
    logger.debug(f"{str_segm}:{str_addr}, {str_content} {xref_segm}:{xref_addr}")
    # Check for Path Structs set by panic_attack.py
    xref_type = fp.get_symbol_type(fp.format_ea_t(xref_addr))
    # DEBUG: xref_type taken as None for offset pointers?
    #if not xref_type:
    #    logger.debug(f"{xref_addr} has no type ({xref_}). Check for unidentified edgecase.")
    #    continue
    if xref_type == "Rust_DebugInfo":
        continue
    else:
        if str_content.endswith(".rs") and ('\\' in str_content or '/' in str_content):
            # NOTE: panic_attack is missing some cases, type isn't being set properly, shown by this.
            logger.debug(f"proj-0xA11C>> If {str_addr} ({str_content}) is a path, you should consider running panic_attack.py first. {xref_addr} type is {xref_type}")
            continue
    if fp.set_symbol_type_to_custom_struct(fp.format_ea_t(xref_addr), slice_struct):
        logger.debug(f"Changed to slice: {xref_segm}:{xref_addr}:{xref_type}->{fp.get_symbol_type(fp.format_ea_t(xref_addr))}")
        # TODO: Double check all of the string lengths based on these structs
        fp.rename_symbol_at_address(fp.format_ea_t(xref_addr),("rsli_" + fp.sanitize_ida_symbol_name(str_content[:30])))

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

# What are we missing?
# What benefit did this bring to the decompilation?
