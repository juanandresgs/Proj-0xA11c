import re
import sys

def extract_readable_strings(binary_data):
    """Extracts readable strings from binary data."""
    return re.findall(rb'[\x20-\x7E]{4,}', binary_data)

def extract_rust_compiler_version(filename):
    """
    Extracts the Rust compiler version from a binary file by first extracting readable strings.
    
    Args:
    filename (str): The path to the binary file to read.
    
    Returns:
    list: A list of all matching Rust compiler version strings found.
    """
    rustc_version_pattern = re.compile(rb"rustc version \d+\.\d+\.\d+ \([0-9a-f]{9} \d{4}-\d{2}-\d{2}\)")
    versions = set()

    with open(filename, 'rb') as file:  # Open file in binary mode
        binary_data = file.read()
        readable_strings = extract_readable_strings(binary_data)
        
    for string in readable_strings:
        matches = rustc_version_pattern.findall(string)
        for match in matches:
            versions.add(match.decode('utf-8'))  # Use add to ensure uniqueness

    return versions

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_binary>")
        sys.exit(1)

    filename = sys.argv[1]
    found_versions = extract_rust_compiler_version(filename)
    if len(found_versions) == 1:
        print("Found Rust compiler version:", found_versions.pop())
    elif len(found_versions) > 1:
        print("Multiple distinct Rust compiler versions found:")
        for version in found_versions:
            print(version)
    else:
        print("No Rust compiler version found in the file.")

