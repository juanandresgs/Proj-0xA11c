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

## Component Order and Status:

| Component                                      | Description                                                                                   | Status   |
|-----------------------------------------------------|-----------------------------------------------------------------------------------------------|----------|
| ./structure_pack.h                                  | Header file containing necessary structures for the project                                   |   ✅     |
| ./identify_rust_binaries.yara                       | YARA rule to identify Rust binaries                                                           | ✅       |
| Metadata |
| ./Metadata/cargo_dependency.py                 | Script to guess dependencies from the binary                                                  | ✅ |
| ./Metadata/compiler_version copy.py                 | Script to extract the Rust compiler version from the binary                                   | x |
 Strings and Slices |
| ./Strings_and_slices/apply_strings.py               | Script to apply string structures in IDA Pro                                                  | ❌       |
| ./Strings_and_slices/panic_attack copy.py           | Script to handle panic attack paths                                                           | x       |
| ./Strings_and_slices/reverse_xmmword_strings copy.py| Script to reverse xmmword strings                                                             | ❌       |
| ./Strings_and_slices/slice_caster.py                | Script to cast slices in IDA Pro                                                              | x       |
| ./Strings_and_slices/string_caster.py               | Placeholder for the final string caster script                                                | ❌       |
| Variables |
| ./parse_unwind copy.py                              | Script to parse unwind information                                                            |  ❌   |
| find_BYREF (JAGS)                                  | Script to find BYREF variables                                                                | ❌       |
| Functions |
| ./parse_pdata_vtable.py                             | Script to parse .pdata and comment references                                                 | x       |

## Work In Progress:


---

# Weirdnesses

## Re: compiler_version.py

- In the case of 4272b75fe652298ab880b2975d94b5a5a139be6c24c1e92136188e1531ce9890, loading the binary in a standard fashion cut off the section with the clang llvm rustc version string. Need to investigate what happened. When manually loaded, it's there. What else is missing?

---

# ROADMAP (Recon2024)

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

# Required Structures

At this time, we are opting for structures being added manually because there's something wrong with IDA Python and it's going to give us a fucking ulcer to try to get it fixed.

Latest structures are kept in structure_pack.h

```
/*
 * Structure name: UNWIND_INFO_HDR (Replacing existing structure because the
 * definition is bad) Description: Fixed UNWIND_INFO structure for PE files,
 * replaces inaccurate IDA Pro implementation Last Updated: 06.18.2024:10:22PM
 * (ET) version 2
 */
struct UNWIND_INFO_HDR {
  unsigned __int8 Version : 3;
  unsigned __int8 Flags : 5;
  unsigned __int8 SizeOfProlog;
  unsigned __int8 CountOfUnwindCodes;
  unsigned __int8 FrameRegister : 4;
  unsigned __int8 FrameRegisterOffset : 4;
  UNWIND_CODE UnwindCodes[];
};

/*
 * Structure name: rust__Slice64
 * Description: Rust slice structure for 64-bit
 */
struct rust__Slice64 {
  char *content;  // Pointer
  __int64 length; // Integer
};

/*
 * Structure name: rust__Slice
 * Description: Rust slice structure for 32-bit
 */
struct rust__Slice {
  char *content;           // Pointer
  unsigned __int32 length; // Integer
};

/*
 * Structure name: rust__String64
 * Description: Rust string structure for 64-bit
 */
struct rust__String64 {
  __int64 capacity; // Integer
  char *content;    // Pointer
  __int64 length;   // Integer
};

/*
 * Structure name: rust__String
 * Description: Rust string structure for 32-bit
 */
struct rust__String4 {
  unsigned __int32 capacity; // Integer
  char *content;             // Pointer
  unsigned __int32 length;   // Integer
};

/*
 * Structure name: rust__DebugInfo64
 * Description: Panic structures
 */
struct rust__DebugInfo64 {
  rust__Slice64 FilePath;
  unsigned __int32 LineNumber;
  unsigned __int32 ColumnNumber;
};

/*
 * Structure name: rust__DebugInfo64
 * Description: Panic structures
 */
struct rust__DebugInfo {
  rust__Slice FilePath;
  unsigned __int32 LineNumber;
  unsigned __int32 ColumnNumber;
};

/*
 * Structure name: rust__ExceptionHandler64
 * Description: (Unidentified )Exception Handler structure for 64-bit
 */
struct rust__ExceptionHandler64 {
  void *Error_or_PanicPath;
  __int64 SetTo1;
  void *FunctionOffset;
};

/*
 * Structure name: rust__ExceptionHandler
 * Description: (Unidentified )Exception Handler structure for 32-bit (untested)
 */
struct rust__ExceptionHandler64 {
  void *Error_or_PanicPath;
  __int64 SetTo1;
  void *FunctionOffset;
};
```
