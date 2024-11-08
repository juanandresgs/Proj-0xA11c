import idaapi
import logging
idaapi.require("FeatureProof")
from FeatureProof.FeatureProof import Middleware
from FeatureProof.TypeInfo import *

# Initialize FeatureProof middleware and set up logging
fp = Middleware()
fp.set_logging_level(level=logging.DEBUG)
logger = fp.logger

def get_all_library_functions_from_pdata() -> list[int]:
    """
    Extracts all function addresses from the .pdata section in the binary.
    
    Returns:
        A list of function addresses found in the .pdata section.
    """
    pdata_section = fp.get_segment_by_name('.pdata')
    if pdata_section is None:
        logger.info("No .pdata section found.")
        return []

    current_addr = pdata_section.start_ea
    end_addr = pdata_section.end_ea
    functions = []

    # Iterate over .pdata section, assuming each entry is 12 bytes (RUNTIME_FUNCTION)
    while current_addr < end_addr:
        func_rva = fp.get_wide_dword(current_addr)
        if func_rva == idaapi.BADADDR:
            logger.warning(f"Invalid RVA at address {hex(current_addr)}. Skipping.")
            current_addr += 12
            continue

        func_ea = fp.get_imagebase() + func_rva
        functions.append(func_ea)
        current_addr += 12

    logger.debug(f"Library functions extracted from .pdata: {[hex(func) for func in functions]}")
    return functions

def get_rest_of_the_functions(
    library_functions: list[int],
    thunk_functions: list[int],
    imported_functions: list[tuple[str, int]]
) -> list[int]:
    """
    Filters out functions from the binary that are already categorized as library, 
    thunk, or imported functions.
    
    Args:
        library_functions: List of library function addresses.
        thunk_functions: List of thunk function addresses.
        imported_functions: List of imported functions, each represented by a tuple (name, address).
    
    Returns:
        A list of function addresses that are not part of library, thunk, or imported functions.
    """
    functions = fp.walk_functions_return_addresses()
    result = []
    
    # Convert library functions to hex strings for exclusion consistency
    library_functions_hex = {hex(lib_func) for lib_func in library_functions}
    
    # Compile a set of excluded functions
    excluded_functions = set(thunk_functions)
    excluded_functions.update(func[1] for func in imported_functions)
    excluded_functions.update(library_functions_hex)
    
    logger.debug(f"Thunk functions: {[hex(func) for func in thunk_functions]}")
    logger.debug(f"Imported functions: {[hex(func[1]) for func in imported_functions]}")
    logger.debug(f"Excluded library functions (hex): {library_functions_hex}")
    
    # Append only functions not in excluded_functions
    for func in functions:
        if func not in excluded_functions:
            result.append(func)
    
    logger.debug(f"Functions not in any category (uncategorized): {[hex(func) for func in result]}")
    return result

# Gather categorized function lists
library_functions = get_all_library_functions_from_pdata()
print(f"Total number of functions in .pdata: {len(library_functions)}")

thunk_functions = fp.get_all_thunk_functions()
print(f"Total number of THUNK functions: {len(thunk_functions)}")

imported_functions = fp.get_all_imports()
print(f"Total number of imported functions: {len(imported_functions)}")

# Retrieve functions not in any excluded categories