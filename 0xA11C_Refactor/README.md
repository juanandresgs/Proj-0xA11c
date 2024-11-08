# Project 0xA11C
Project 0xA11C ('Oxalic') is an open-source project that aims to provide tools for reverse engineering Rust binaries. The project is in active development alongside a series of conference talks to serve as a discussion of the problems associated with reverse engienering Rust with current tooling, incremental developments, and a call to action. In the process of developing 0xA11C tools, we've developed and underlying middleware (FeatureProof) meant to address compatibility issues across different versions of IDA Pro's IDAPython APIs (and perhaps someday provide cross-compatibility with other RE platforms).

As of November 2024, it's important to note that the quality of decompilation for Rust code in IDA Pro is still quite poor, plagued by dead store variables, bad function prototypes, false equivalences, etc. The tools provided by Project 0xA11C are meant to surface useful information and position it for further analysis but they cannot fully compensate for decompilation issues. (At this time, Binary Ninja provides improved decompilation for Rust binaries, but it's not perfect either).

Both Project 0xA11C and FeatureProof welcome contributions, fixes, patches, and suggestions.

# Tools

## Setup
After cloning the repo, make sure you run `git submodule update --init --recursive`. This will pull the FeatureProof submodule.
- [FeatureProof](https://github.com/juanandresgs/FeatureProof.git)

Before running the 0xA11C scripts, please import the 'structure_pack.h' file in IDA Pro by click on File -> Load File -> Parse C header file (Ctrl+F9). This file contains the necessary structures for the scripts to work.

Where symbols are available, we recommend switching name demangling settings: Options -> Demangled Names -> Show demangled names as: Names.

## Component Status

| Component  | Description | Status |
|------------|-------------|--------|
| structure_pack.h  | Header file containing necessary structures for the project | ✅ |
| identify_rust_binaries.yara | YARA rule to identify Rust binaries | ✅ |
| Metadata |
| cargo_dependency.py | Extract dependencies | ✅ |
| compiler_version.py | Extract Rust compiler version | X |
| Strings and Slices |
| apply_strings.py | Apply Rust string and slice structures | ❌ |
| panic_attack.py | Handle panic macro paths | X |
| reverse_xmmword_strings.py| Reverse xmmword strings | ❌ |
| slice_caster.py | Script to cast slices in IDA Pro | X |
| string_caster.py | Placeholder for the final string caster script | ❌ |
| Variables |
| parse_unwind.py | Script to parse unwind information | ❌ |
| find_BYREF (JAGS) | Script to find BYREF variables | ❌ |
| Functions |
| parse_pdata_vtable.py | Parse .pdata and comment references | X |

## Work In Progress
| Component  | Description | Status |
|------------|-------------|--------|

---

# Weirdnesses

## Re: compiler_version.py

- In the case of 4272b75fe652298ab880b2975d94b5a5a139be6c24c1e92136188e1531ce9890, loading the binary in a standard fashion cut off the section with the clang llvm rustc version string. Need to investigate what happened. When manually loaded, it's there. What else is missing?
- [ ] (Retest post refactoring)

---

# FINAL ROADMAP (Ekoparty2024)

## Find Samples

[x]- identify_rust_binaries.yara

## Metadata

[x]- cargo_dependency.py
[x]- compiler_version.py
[FAILED]- structure_creator.py (+structure_pack.h)

## Apply Structures and Gain info

[x]- parse_unwind.py (Dependent on UNWIND_INFO_HDR structure)
[ ]- define_string_structs.py (To be replaced by structure_creator, when IDAPython stops being obnoxious)
[ ]- apply_strings.py (NF) (Dependent on rust**Slice/64 and rust**String/64 structures)

## Decompiler Improvements

[ ]- reverse_xmmword_strings.py (NEEDS REFACTORING)
[ ]- find_BYREF (JAGS) (WIP)

## Recover Metadata

[x]- panic_attack.py
