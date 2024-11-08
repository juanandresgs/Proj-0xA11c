import idaapi
import logging
idaapi.require("FeatureProof")
from FeatureProof.FeatureProof import Middleware
from FeatureProof.TypeInfo import *

# Initialize FeatureProof middleware and set up logging
fp = Middleware()
fp.set_logging_level(level=logging.INFO)
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
        
        func_name = fp.get_function_name_from_address(safe_int_conversion(func_ea))
        if not ("main" in func_name.lower() or "start" in func_name.lower()):
            functions.append(func_ea)
        else:
            logging.info(f"Skipped function name: {func_name} at: {func_ea}")
        current_addr += 12
    
    return functions

def get_rest_of_the_functions(
    library_functions: list[int],
    thunk_functions: list[int]
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
    # excluded_functions = set()
    # excluded_functions.update(func[1] for func in imported_functions)
    excluded_functions.update(library_functions_hex)
    
    # Convert excluded_functions to uppercase to match case in functions
    excluded_lower = {item.lower() for item in excluded_functions}
    
    logging.info(f"Total number of functions is: {len(functions)}")
    logging.info(f"The total number of filtered functions is: {len(excluded_lower)}")
    
    # Append only functions not in excluded_functions
    for func in functions:
        if func.lower() not in excluded_lower:
            result.append(func)
    
    return result

def safe_int_conversion(value):
    if isinstance(value, str):  # Convert from hexadecimal string
        return int(value, 16)
    elif isinstance(value, int):  # Already an integer
        return value
    else:
        logging.error(f"Value must be a string or an integer. Got {value}")
    
def move_functions_to_folder(functions_addresses, folder_name):
    
    fp.create_folder(folder_name)
    
    fid = fp.check_folder_exists(folder_name)
    
    if fid:
        for addr in functions_addresses:
            func_name = fp.get_function_name_from_address(safe_int_conversion(addr))
            if func_name:
                fp.move_to_folder(func_name, folder_name)
            else:
                logging.debug(f"Couldn't find function name at address: {addr}")
    else:
        logging.error(f"Couldn't create folder named: {folder_name}")
        return
    
    logging.info(f"Moved functions to a folder named: {folder_name}")
        

# Gather categorized function lists
library_functions = get_all_library_functions_from_pdata()
logging.info(f"Total number of functions in .pdata: {len(library_functions)}")

thunk_functions = fp.get_all_thunk_functions()
logging.info(f"Total number of THUNK functions: {len(thunk_functions)}")

imported_functions = fp.get_all_imports()
logging.info(f"Total number of imported functions: {len(imported_functions)}")

# Retrieve functions not in any excluded categories
rest_of_the_functions = get_rest_of_the_functions(library_functions, thunk_functions)
logging.info(f"Number of functions not in any of these categories: {len(rest_of_the_functions)}")

move_functions_to_folder(library_functions, "Probably Library Functions")
move_functions_to_folder(thunk_functions, "Thunk Functions")
# move_functions_to_folder([func[1] for func in imported_functions], "Imported Functions")