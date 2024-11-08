# Project 0xA11C Tools

# Component Status

## Dependency:

- [FeatureProof](https://github.com/juanandresgs/FeatureProof.git)
  - After cloning, make sure you run `git submodule update --init --recursive`

## Works:

- structure_pack.h
- identify_rust_binaries.yara
- cargo_dependency.py
- compiler_version.py
- parse_unwind.py
- panic_attack.py (JAGS)

## Needs testing

- define_string_structs.py
- reverse_xmmword_strings.py (NF)

## Work In Progress:

- apply_strings.py (NF/JAGS -- NEEDS REFACTORING)
- find_BYREF (JAGS)

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
