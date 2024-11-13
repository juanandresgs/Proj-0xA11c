import idaapi
idaapi.require("FeatureProof")
from FeatureProof.FeatureProof import Middleware
from FeatureProof.TypeInfo import *

# Initialize FeatureProof middleware and set up logging
fp = Middleware()
fp.set_logging_level("DEBUG")
logger = fp.logger

def get_all_funcs_with_eh_from_pdata() -> list[int]:
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
        
        func_name = fp.get_function_name_from_address(func_ea)
        if not ("main" in func_name.lower() or "start" in func_name.lower()):
            functions.append(func_ea)
        else:
            logger.debug(f"Skipped function name: {func_name} at: {func_ea}")
        current_addr += 12
    
    return functions

def get_rest_of_the_functions(
    funcs_w_eh: list[int],
    thunk_functions: list[int]
) -> list[int]:
    """
    Filters out functions from the binary that are already categorized as library, 
    thunk, or imported functions.
    
    Args:
        funcs_w_eh: List of library function addresses.
        thunk_functions: List of thunk function addresses.
        imported_functions: List of imported functions, each represented by a tuple (name, address).
    
    Returns:
        A list of function addresses that are not part of library, thunk, or imported functions.
    """
    functions = fp.walk_functions_return_addresses()
    result = []
    
    # Convert library functions to hex strings for exclusion consistency
    funcs_w_eh_hex = {hex(lib_func) for lib_func in funcs_w_eh}
    
    # Compile a set of excluded functions
    excluded_functions = set(thunk_functions)
    # excluded_functions = set()
    # excluded_functions.update(func[1] for func in imported_functions)
    excluded_functions.update(funcs_w_eh_hex)
    
    # Convert excluded_functions to uppercase to match case in functions
    excluded_lower = {item.lower() for item in excluded_functions}
    
    logger.info(f"Total number of functions is: {len(functions)}")
    logger.info(f"The total number of filtered functions is: {len(excluded_lower)}")
    
    # Append only functions not in excluded_functions
    for func in functions:
        if func.lower() not in excluded_lower:
            result.append(func)
    
    return result
    
def move_functions_to_folder(functions_addresses, folder_name):
    logger.debug(f"Starting to move {len(functions_addresses)} functions to folder: {folder_name}")
    
    if not fp.check_folder_exists(folder_name):
        logger.debug(f"Folder '{folder_name}' does not exist, creating it")
        fp.create_folder(folder_name)
    else:
        logger.debug(f"Folder '{folder_name}' already exists")
    
    successful_moves = 0
    failed_moves = 0
    
    for addr in functions_addresses:
        logger.debug(f"Processing address: {addr}")
        print(type(addr))
        addr = fp.format_address(addr)
        print(type(addr))
        func_name = fp.get_function_name_from_address(addr)
        
        if func_name:
            logger.debug(f"Found function name '{func_name}' at address {addr}")
            if fp.move_to_folder(func_name, folder_name):
                logger.debug(f"Successfully moved function '{func_name}' to folder '{folder_name}'")
                successful_moves += 1
            else:
                logger.debug(f"Failed to move function '{func_name}' to folder '{folder_name}'")
                failed_moves += 1
        else:
            logger.debug(f"Couldn't find function name at address: {addr}")
            failed_moves += 1
            
    logger.info(f"Finished moving functions to folder '{folder_name}':")
    logger.info(f"  - Successfully moved: {successful_moves} functions")
    logger.info(f"  - Failed to move: {failed_moves} functions")
        

# Gather categorized function lists
funcs_w_eh = get_all_funcs_with_eh_from_pdata()
logger.info(f"Total number of functions in .pdata: {len(funcs_w_eh)}")

thunk_functions = fp.get_all_thunk_functions()
logger.info(f"Total number of THUNK functions: {len(thunk_functions)}")

imported_functions = fp.get_all_imports()
logger.info(f"Total number of imported functions: {len(imported_functions)}")

# Retrieve functions not in any excluded categories
rest_of_the_functions = get_rest_of_the_functions(funcs_w_eh, thunk_functions)
logger.info(f"Number of functions not in any of these categories: {len(rest_of_the_functions)}")

move_functions_to_folder(funcs_w_eh, "Funcs w ExceptionHandling")
move_functions_to_folder(thunk_functions, "Thunks and Jumps")
# move_functions_to_folder([func[1] for func in imported_functions], "Imported Functions")