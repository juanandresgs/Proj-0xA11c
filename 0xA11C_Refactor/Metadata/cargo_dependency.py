import idaapi
import re
idaapi.require("FeatureProof.FeatureProof")
from FeatureProof.FeatureProof import Middleware

fp = Middleware()
fp.set_logging_level(level=logging.INFO)
logger = fp.logger

def guess_dependencies():
    regexes = [
        rb'index.crates.io.[^\\\/]+.([^\\\/]+)',
        rb'registry.src.[^\\\/]+.([^\\\/]+)'
    ]
    readable_strings = fp.get_all_strings(min_length=4)
    result = set()

    for addr, string in readable_strings:
        for reg in regexes:
            regex = re.compile(reg)
            matches = regex.findall(string.encode('utf-8'))
            for match in matches:
                result.add(match.decode('utf-8'))  # Use add to ensure uniqueness
    return result

def guess_toolchain():
    known_heuristics = {
        b"Mingw-w64 runtime failure": "Mingw-w64",
        b"_CxxThrowException": "windows-msvc",
        b".CRT$": "windows-msvc",
        b"/checkout/src/llvm-project/libunwind/src/DwarfInstructions.hpp": "linux-musl",
    }

    for item, value in known_heuristics.items():
        if item in fp.get_all_strings(min_length=4):
            return value

    return None


def main():

    matches = guess_dependencies()
    if matches:
        logger.info("Rust dependecies:")
        for match in matches:
            logger.info(f"{match}")
    else:
        logger.warn("No Rust crate dependency strings found.")

    toolchain = guess_toolchain()
    if toolchain:
        logger.info(f"Rust toolchain: {toolchain}")
    else:
        logger.warn("No toolchain was found")

if __name__ == "__main__":
    main()
