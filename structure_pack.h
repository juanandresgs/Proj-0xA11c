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
