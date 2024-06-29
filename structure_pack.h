// Structure pack to keep updated definitions.
// If possible, have scripts source from here instead of implementing their own
// copies.
//

/*
 * Structure name: UnwindInfo
 * Description: Fixed UNWIND_INFO structure for PE files, replaces inaccurate
 * IDA Pro implementation Last Updated: 06.18.2024:10:22PM (ET)
 * version 2
 */
struct UnwindInfo {
  unsigned __int8 Version : 3;
  unsigned __int8 Flags : 5;
  unsigned __int8 SizeOfProlog;
  unsigned __int8 CountOfUnwindCodes;
  unsigned __int8 FrameRegister : 4;
  unsigned __int8 FrameRegisterOffset : 4;
  UNWIND_CODE UnwindCodes[];
};

/*
 * Structure name: Rust::Slice64
 * Description: Rust slice structure for 64-bit
 */
struct Rust::Slice64 {
  unsigned long long content; // Pointer
  unsigned long long length;  // Integer
};

/*
 * Structure name: Rust::String64
 * Description: Rust string structure for 64-bit
 */
struct Rust::String64 {
  unsigned long long capacity; // Integer
  unsigned long long content;  // Pointer
  unsigned long long length;   // Integer
};
