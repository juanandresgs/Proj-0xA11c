import idaapi
import idc
import idautils

def get_function_byref_vars(ea):
    func = idaapi.get_func(ea)
    if not func:
        print("Function not found!")
        return []
    
    frame_id = idc.get_func_attr(ea, idc.FUNCATTR_FRAME)
    if frame_id == idc.BADADDR:
        print("Function frame not found!")
        return []
    
    frame = idaapi.get_frame(func)
    if not frame:
        print("Function frame not found!")
        return []

    # Hex-Rays variable mapping (displacement value to variable name)
    hexrays_var_mapping = {
        40: "v11[2]",  # var_70
        64: "v13[11]", # var_58
    }

    byref_vars = []

    print(f"Function: {func.start_ea:X} - {func.end_ea:X}")
    print(f"Frame ID: {frame_id}")

    # Iterate through each instruction in the function
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for i in range(2):  # Check both operands
                if idc.get_operand_type(head, i) == idc.o_displ:
                    displ_value = idc.get_operand_value(head, i)
                    opnd_text = idc.print_operand(head, i)
                    print(f"Instruction at {head:X}: Operand {i} ({opnd_text}) is a displacement with value {displ_value}")
                    
                    # Map displacement value to variable names
                    var_name = idc.get_member_name(frame_id, displ_value)
                    hexrays_var_name = hexrays_var_mapping.get(displ_value, "Unknown")

                    if var_name:
                        print(f"Displacement value {displ_value} maps to variable {var_name} (Hex-Rays equivalent: {hexrays_var_name})")
                        byref_vars.append((var_name, hexrays_var_name))
    
    return byref_vars

# Example usage:
ea = idc.get_screen_ea()  # Get the address of the current function
byref_vars = get_function_byref_vars(ea)
if byref_vars:
    print("BYREF Variables:")
    for var, hexrays_var in byref_vars:
        print(f"- {var} (Hex-Rays equivalent: {hexrays_var})")
else:
    print("No BYREF variables found.")

