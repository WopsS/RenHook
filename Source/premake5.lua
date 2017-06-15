project("RenHook")
    kind("StaticLib")
    language("C++")
    pchheader("RenHook/RenHook.hpp")
    pchsource("RenHook/RenHook.cpp")

    if buildpath ~= nil then
        targetdir(buildpath())
    end

    filter({ "configurations:Debug" })
        symbols("On")

    filter({ "configurations:Release" })
        symbols("Off")

    filter({})

    includedirs({ ".", "../Dependencies/Capstone/Capstone/include" })   
    links({ "Capstone" })

    files({  "**.cpp", "**.hpp" })