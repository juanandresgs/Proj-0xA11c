import idaapi
idaapi.require("IDuhLib")
from IDuhLib import *

############ Path Handler ############
# Version 0.0.1                      #
######################################

# Relevant structures:
#TODO: Determine if the bitness matters
'''
    struct rust::DebugInfo
    {
     char *path;
     int line1;
     int line2;
     int line3;
    };
'''

#######################################
#GOAL:Make sure structure is added
#######################################

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
    rename_symbol_at_address(address, sanitized_name)

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
            print(f"Potential Path struct at: ", x) # DEBUG
            #TODO: This needs further heuristics, there are instances of rdata references followed by other strings

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




