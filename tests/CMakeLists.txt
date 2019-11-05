add_executable(Tests "")

file(GLOB_RECURSE HEADERS *.hpp)
file(GLOB_RECURSE SOURCES *.cpp)

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${HEADERS} ${SOURCES})

target_include_directories(Tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(Tests PRIVATE ${HEADERS} ${SOURCES})
target_link_libraries(Tests PRIVATE Catch2::Catch2 RenHook)
