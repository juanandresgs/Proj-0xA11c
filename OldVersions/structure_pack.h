/*
 * Structure name: UNWIND_INFO_HDR (Replacing existing structure because the
 * definition is bad) Description: Fixed UNWIND_INFO structure for PE files,
 * replaces inaccurate IDA Pro implementation Last Updated: 06.18.2024:10:22PM
 * (ET) version 2
 * UNWIND_CODE replicated as preprocessing dependency
 */
#pragma pack(push, 1)  // Set alignment to 1 byte
struct UNWIND_CODE
{
  unsigned __int8 op_code : 4;
  unsigned __int8 op_info : 4;
  unsigned __int16 offset_in_prolog;
};
#pragma pack(pop)

struct UNWIND_INFO_HDR {
  unsigned __int8 Version : 3;
  unsigned __int8 Flags : 5;
  unsigned __int8 SizeOfProlog;
  unsigned __int8 CountOfUnwindCodes;
  unsigned __int8 FrameRegister : 4;
  unsigned __int8 FrameRegisterOffset : 4;
  struct UNWIND_CODE UnwindCodes[];
};

/*
 * Structure name: Rust_Slice64
 * Description: Rust slice structure for 64-bit
 */
#pragma pack(push, 1)  // Set alignment to 1 byte
struct Rust_Slice64 {
  char *content;  // Pointer
  __int64 length; // Integer
};
#pragma pack(pop)

/*
 * Structure name: Rust_Slice
 * Description: Rust slice structure for 32-bit
 */
#pragma pack(push, 1)  // Set alignment to 1 byte
struct Rust_Slice {
  char *content;           // Pointer
  unsigned __int32 length; // Integer
};
#pragma pack(pop)

/*
 * Structure name: Rust_String64
 * Description: Rust string structure for 64-bit
 */
#pragma pack(push, 1)  // Set alignment to 1 byte
struct Rust_String64 {
  __int64 capacity; // Integer
  char *content;    // Pointer
  __int64 length;   // Integer
};
#pragma pack(pop)

/*
 * Structure name: Rust_String
 * Description: Rust string structure for 32-bit
 */
#pragma pack(push, 1)  // Set alignment to 1 byte
struct Rust_String {
  unsigned __int32 capacity; // Integer
  char *content;             // Pointer
  unsigned __int32 length;   // Integer
};
#pragma pack(pop)

/*
 * Structure name: Rust_DebugInfo64
 * Description: Panic structures
 */
struct Rust_DebugInfo64 {
  struct Rust_Slice64 FilePath;
  unsigned __int32 LineNumber;
  unsigned __int32 ColumnNumber;
};

/*
 * Structure name: Rust_DebugInfo64
 * Description: Panic structures
 */
struct Rust_DebugInfo {
  struct Rust_Slice FilePath;
  unsigned __int32 LineNumber;
  unsigned __int32 ColumnNumber;
};

// EXPERIMENTAL
/*
 * Structure name: Rust_ExceptionHandler64
 * Description: (Unidentified )Exception Handler structure for 64-bit
 */
#pragma pack(push, 1)  // Set alignment to 1 byte
struct Rust_ExceptionHandler64 {
    void *Error_or_PanicPath;
    __int64 SetToI;
    void *FunctionOffset;
};
#pragma pack(pop)

/*
 * Structure name: Rust_ExceptionHandler
 * Description: (Unidentified )Exception Handler structure for 32-bit (untested)
 */
#pragma pack(push, 1)  // Set alignment to 1 byte
struct Rust_ExceptionHandler {
    void *Error_or_PanicPath;
    __int64 SetToI;
    void *FunctionOffset;
};
#pragma pack(pop)

