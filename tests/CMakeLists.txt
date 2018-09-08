add_executable(tests "")

file(GLOB_RECURSE HEADERS *.hpp)
file(GLOB_RECURSE SOURCES *.cpp)

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${HEADERS} ${SOURCES})

target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_sources(tests PRIVATE ${HEADERS} ${SOURCES})
target_link_libraries(tests PRIVATE Catch2::Catch2 renhook)