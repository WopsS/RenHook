project("Capstone")
    defines({ "CAPSTONE_X86_ATT_DISABLE_NO", "CAPSTONE_DIET_NO", "CAPSTONE_X86_REDUCE_NO", "CAPSTONE_HAS_ARM", "CAPSTONE_HAS_ARM64", "CAPSTONE_HAS_MIPS", "CAPSTONE_HAS_POWERPC", "CAPSTONE_HAS_SPARC", "CAPSTONE_HAS_SYSZ", "CAPSTONE_HAS_X86", "CAPSTONE_HAS_XCORE", "CAPSTONE_USE_SYS_DYN_MEM", "WIN32", "_DEBUG", "_LIB" })
    kind("StaticLib")
    language("C")
    removedefines({ "_CRT_SECURE_NO_WARNINGS" })

    if buildpath ~= nil then
        targetdir(buildpath())
    end

    filter({ "configurations:Debug" })
        symbols("On")

    filter({ "configurations:Release" })
        symbols("Off")

    filter({})

    includedirs({ "Capstone/include" })

    files({  "Capstone/arch/**.c", "Capstone/cs.c", "Capstone/MCInst.c", "Capstone/MCInstrDesc.c", "Capstone/MCRegisterInfo.c", "Capstone/SStream.c" , "Capstone/utils.c" })