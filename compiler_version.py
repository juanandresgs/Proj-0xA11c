import idaapi
import requests
idaapi.require("IDuhLib")
from IDuhLib import *

def get_version_from_commit(commit: str):
    url = f"https://github.com/rust-lang/rust/branch_commits/{commit}"
    res = requests.get(url, timeout=20).text
    regex = re.compile(r'href="/rust-lang/rust/releases/tag/([0-9\.]+)"')

    if not regex.findall(res):
        return None

    return regex.findall(res)[-1]

def extract_rust_compiler_version():
    """
    Extracts the Rust compiler version from the binary.

    Returns:
    list: A list of all matching Rust compiler version strings found.
    """
    # For stripped binaires the version can be found using the commit. This regex should be able to find it
    
    pattern = rb"rustc/([a-z0-9]{40})"
    regex = re.compile(pattern)
    commits = set()
    readable_strings = get_all_strings(min_length=4)
    
    for addr, string in readable_strings:
        matches = regex.findall(string.encode('utf-8'))
        for match in matches:
            commits.add(match.decode('utf-8'))  # Use add to ensure uniqueness
    
    return commits

def main():
    commits = extract_rust_compiler_version()
    if len(commits) == 1:
        commit = commits.pop()
        version = get_version_from_commit(commit)
        if version is None:
            print(f"No tag matching this commit {commit}, getting latest version")
        else:
            print(f"rustc version: {version}, for commit: {commit}")
        
    elif len(commits) > 1:
        print("Multiple distinct Rust compiler versions found:")
        for comm in commits:
            print(comm)
    else:
        print("No Rust compiler version found in the binary.")

if __name__ == "__main__":
    main()

