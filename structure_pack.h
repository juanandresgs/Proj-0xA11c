// Structure pack to keep updated definitions.
// If possible, have scripts source from here instead of implementing their own
// copies.
//

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
  char *content;             // Pointer
  unsigned long long length; // Integer
};

/*
 * Structure name: rust__String64
 * Description: Rust string structure for 64-bit
 */
struct rust__String64 {
  unsigned long long capacity; // Integer
  char *content;               // Pointer
  unsigned long long length;   // Integer
};

/*
 * Structure name: rust__DebugInfo64
 * Description: Panic structures
 */
struct rust__DebugInfo64 {
  char *FilePath;
  DWORD _pad[2];
  unsigned __int32 LineNumber;
  unsigned __int32 ColumnNumber;
};
