# Project 0xA11C Tools

# Component Status

## Dependency:

- [IDuhLib](https://github.com/juanandresgs/IDuh.git)

## Works:

- identify_rust_binaries.yara
- cargo_dependency.py
- compiler_version.py

## Needs testing

- parse_unwind.py
- define_string_structs.py
- reverse_xmmword_strings.py

## UNUPDATED

- structure_pack.h

## Work In Progress:

- PathHandler (JAGS)
- apply_strings.py (NF)
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

[ ]- parse_unwind.py (Dependent on UNWIND_INFO_HDR structure)
[ ]- define_string_structs.py (To be replaced by structure_creator)
[ ]- apply_strings.py (NF) (dependent on structure_creator)

## Decompiler Improvements

[ ]- reverse_xmmword_strings.py
[ ]- find_BYREF (JAGS)

##

[ ]- PathHandler

# Required Structures

At this time, we are opting for structures being added manually because there's something wrong with IDA Python and it's going to give us a fucking ulcer to try to get it fixed.

## Updated UNWIND_INFO_HDR

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
struct rust::Slice64 {
  unsigned long long content; // Pointer
  unsigned long long length;  // Integer
};

/*
 * Structure name: rust__String64
 * Description: Rust string structure for 64-bit
 */
struct rust::String64 {
  unsigned long long capacity; // Integer
  unsigned long long content;  // Pointer
  unsigned long long length;   // Integer
};
```
