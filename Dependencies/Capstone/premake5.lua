project("Capstone")
    defines({ "CAPSTONE_HAS_X86", "CAPSTONE_USE_SYS_DYN_MEM", "WIN32" })
    kind("StaticLib")
    language("C")
    removedefines({ "_CRT_SECURE_NO_WARNINGS" })

    if buildpath ~= nil then
        targetdir(buildpath())
    end

    includedirs({ "Capstone/include" })

    files({  "Capstone/arch/X86/**.c", "Capstone/cs.c", "Capstone/MCInst.c", "Capstone/MCInstrDesc.c", "Capstone/MCRegisterInfo.c", "Capstone/SStream.c" , "Capstone/utils.c" })