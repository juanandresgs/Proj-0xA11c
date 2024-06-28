import idaapi
idaapi.require("IDuhLib")
from IDuhLib import *

def extract_rust_compiler_version():
    """
    Extracts the Rust compiler version from the binary.

    Returns:
    list: A list of all matching Rust compiler version strings found.
    """
    pattern = rb"rustc version \d+\.\d+\.\d+ \([0-9a-f]{9} \d{4}-\d{2}-\d{2}\)"
    regex = re.compile(pattern)
    versions = set()
    readable_strings = get_all_strings(min_length=4)
    
    for addr, string in readable_strings:
        matches = regex.findall(string.encode('utf-8'))
        for match in matches:
            versions.add(match.decode('utf-8'))  # Use add to ensure uniqueness

    return versions

def main():
    found_versions = extract_rust_compiler_version()
    if len(found_versions) == 1:
        print("Found Rust compiler version:", found_versions.pop())
    elif len(found_versions) > 1:
        print("Multiple distinct Rust compiler versions found:")
        for version in found_versions:
            print(version)
    else:
        print("No Rust compiler version found in the binary.")

if __name__ == "__main__":
    main()

