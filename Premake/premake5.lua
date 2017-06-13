require("premake", ">=5.0.0-alpha11")

basepath = path.getdirectory(os.getcwd());
buildpath = function(p) return path.join(basepath, "Build", "%{cfg.buildcfg}", p).."/" end
sourcepath = function() return path.join(basepath, "Source").."/" end

workspace("RenHook")
    architecture("x86_64")
    characterset("Unicode")
    configurations({ "Debug", "Release" })
    defines({ "_CRT_SECURE_NO_WARNINGS" })
    flags({ "C++14" })
    location("Project")

    filter({ "configurations:Release" })
        optimize("On")

    filter({})

    include(sourcepath())