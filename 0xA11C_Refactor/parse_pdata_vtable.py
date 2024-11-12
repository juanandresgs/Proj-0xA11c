import idaapi
import logging
idaapi.require("FeatureProof.FeatureProof")
from FeatureProof.FeatureProof import Middleware
from FeatureProof.TypeInfo import BADADDR

fp = Middleware()
fp.set_logging_level(level=logging.INFO)
logger = fp.logger

def parse_pdata_and_comment_references():
    # Get the .pdata section
    pdata_section = fp.get_segment_by_name('.pdata')
    if pdata_section is None:
        logging.info("No .pdata section found.")
        return

    # Define the start and end of the .pdata section
    current_addr = pdata_section.start_ea
    end_addr = pdata_section.end_ea

    # Iterate over the .pdata section, assuming 12 bytes per RUNTIME_FUNCTION entry
    while current_addr < end_addr:
        # Read function RVA from the current .pdata entry
        func_rva = fp.get_wide_dword(current_addr)
        if func_rva == BADADDR:
            logging.info(f"Invalid RVA at address {hex(current_addr)}. Skipping.")
            current_addr += 12  # Move to the next entry
            continue

        # Calculate the effective address of the function
        func_ea = fp.get_imagebase() + func_rva
        func_name = fp.get_function_name_from_address(func_ea)
        
        if func_name:
            vtable_addr = current_addr
            comment_text = f"{func_name} - Part of vtable (probably library function), Vtable Address: {hex(vtable_addr)}"
            
            # Use FeatureProof's function to find all references to this function
            xrefs = fp.get_all_xref_addresses_to_this_address(func_ea)
            for ref in xrefs:
                # Add the comment at each reference address
                logging.info("ref:{}".format(fp.format_ea_t(ref)))
                fp.set_comment_at_address(fp.format_ea_t(ref), comment_text, is_repeatable=True)
                # logging.info(f"Added comment at ref: '{comment_text}'")
                
            # Add an anterior (repeatable) comment to the function itself
            logging.info("function:{}".format(func_ea))
            fp.set_comment_at_address(func_ea, comment_text, is_repeatable=True)
            # logging.info(f"Added function comment for {func_name} at {hex(func_ea)}")
        else:
            logging.info(f"No function name found for address {hex(func_ea)}")

        # Move to the next entry (12 bytes for RUNTIME_FUNCTION)
        current_addr += 12

# Execute the main function
parse_pdata_and_comment_references()