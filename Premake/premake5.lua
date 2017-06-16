require("premake", ">=5.0.0-alpha11")

basepath = path.getdirectory(os.getcwd());
buildpath = function(p) return path.join(basepath, "Build", "%{cfg.buildcfg}", p).."/" end
dependenciespath = function(p) return path.join(basepath, "Dependencies", p).."/" end
sourcepath = function() return path.join(basepath, "Source").."/" end

workspace("RenHook")
    architecture("x86_64")
    characterset("Unicode")
    configurations({ "Debug", "Release" })
    defines({ "_CRT_SECURE_NO_WARNINGS" })
    flags({ "C++14" })
    location("Projects")
    startproject("RenHook")

    filter({ "configurations:Release" })
        optimize("On")

    filter({})

    group("Dependencies")
        include(dependenciespath("Capstone"))
        include(dependenciespath("ODLib/Source"))

    group("")
        include(sourcepath())