import idaapi
idaapi.require("IDuhLib")
from IDuhLib import *

############ Path Handler ############
# Version 0.0.1                      #
######################################

#######################################
#GOAL:Make sure structure is added
#######################################
#######################################
#GOAL:Find Path Strings
#######################################

# Prefixes: /rust/, /rustc/, C:\, library, src
paths = get_strings_intersection_of_start_and_end("/rustc/",".rs")
paths.update(get_strings_intersection_of_start_and_end("src",".rs"))
paths.update(get_strings_intersection_of_start_and_end("library",".rs"))
paths.update(get_strings_intersection_of_start_and_end("C:\\",".rs"))
paths.update(get_strings_intersection_of_start_and_end("/rust/",".rs"))

#LOGIC:Or do we just go with ends with .rs?
missing_elements = [item for item in get_strings_ending_with(".rs") if item not in paths]
print("DEBUG: These are potential path misses")
print(missing_elements) #DEBUG

#LOGIC:Well what's the next heuristic? That it has XREFs in its own segment that can fit into our debugInfo struct?

#######################################
#GOAL:Rename the path symbol
#######################################

#TODO: ADD LOGIC TO HANDLE DUPLICATE SYMBOL NAMES
for s in paths:
    address = s[0]
    sanitized_name = "Path_" + sanitize_ida_symbol_name(s[1])
    rename_symbol_at_address(address, sanitized_name)

#######################################
#GOAL:Get all XREFs
#######################################

for addr, symbol in paths:
    addr = format_ea_t(addr)
    path_segment = get_segment_name_at_address(addr)
    name = "rdi_" + sanitize_ida_symbol_name(symbol)
    xrefs = get_all_xref_addresses_to_this_address(addr)
    print(name) # DEBUG
    for x in xrefs:
        x = format_ea_t(x)
        segment = get_segment_name_at_address(x)
        print(x, segment) # DEBUG

#######################################
#Check that they’re in the same section as the string itself
#######################################
#GOAL:Change type to rust::DebugInfo struct
#######################################
#GOAL:Rename struct symbol to include final part of path, filename, and coordinates (x,y,z)
#######################################


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




