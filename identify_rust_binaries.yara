
rule Rust {
    meta:
        description = "Rule to detect Rust Binaries (PE<ELF<MACOS)"
        author = "Nicole"
        date = "20-05-2024"
        version = "1.0"

    strings:

        $a01 = "RUST_MIN_STACK"
        $a02 = "RUST_BACKTRACE"
        $a03 = "RUST_LOG"
        $z01 = "dropbox_watchdog"

    condition:
        (
            // uint16be(0) == 0x4D5A or //Windows Portable Executable
            // uint32(0) == 0x7F454C46 or //Linux ELF
            // uint32(0) == 0xFEEDFACE or // macOS Mach-O 32-bit
            // uint32(0) == 0xFEEDFACF or // macOS Mach-O 64-bit
            // uint32(0) == 0xCAFEBABE // macOS Mach-O universal binary

            (uint16(0) == 0x5a4d) or 
			(uint32(0)==0x464c457f) or 
			(uint32(0) == 0xfeedfacf) or 
			(uint32(0) == 0xcffaedfe) or 
			(uint32(0) == 0xfeedface) or 
			(uint32(0) == 0xcefaedfe) 
        )
        and(
            1 of ($a*) and not any of ($z*)
        )
        
}
