import re
import string
import sys

def extract_strings(filename):
    with open(filename, 'rb') as file:
        text = file.read()
    printable = set(bytes(string.printable, 'ascii'))
    text_segments = []
    current_segment = []
    for byte in text:
        if byte in printable:
            current_segment.append(chr(byte))
        elif current_segment:
            text_segments.append(''.join(current_segment))
            current_segment = []
    return text_segments

def find_crate_dependencies(text_segments):
    # regex_string = r".cargo(/|\\)registry(/|\\)src(/|\\).*?-[a-f0-9]{16}(/|\\)(.*?\d+.\d+.\d+)"
    # regex_string = r"\.cargo[/\\]registry[/\\]src[/\\][^\/\\]+[/\\]([^\/\\]+)[-]([0-9a-zA-Z.\-_]+)[/\\]"
    regex_string = r".cargo(/|\\)registry(/|\\)src(/|\\).*?-[a-f0-9]{16}(/|\\)(.*?\d+.\d+.\d+)"
    matches = set()
    for segment in text_segments:
        matches.update(re.findall(regex_string, segment))
    return sorted(matches)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_binary>")
        sys.exit(1)

    filename = sys.argv[1]
    strings = extract_strings(filename)
    dependencies = find_crate_dependencies(strings)

    if dependencies:
        for dependency in dependencies:
            print(dependency[-1])
    else:
        print("No Rust crate dependency strings found.")