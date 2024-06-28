import idaapi
idaapi.require("IDuhLib")
from IDuhLib import *

def main():
    pattern = r".cargo(/|\\)registry(/|\\)src(/|\\).*?-[a-f0-9]{16}(/|\\)(.*?\d+.\d+.\d+)"
    matches = get_strings_matching_regex(pattern)
    
    if matches:
        for addr, match in matches:
            print(f"Address: {addr}, Match: {match}")
    else:
        print("No Rust crate dependency strings found.")

if __name__ == "__main__":
    main()
