cmake_minimum_required(VERSION 3.16)
project(extrestore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# When wanting to use a local checkout, set `FETCHCONTENT_SOURCE_DIR_SERENITY` as a CMake option.
FetchContent_Declare(
    serenity
    GIT_REPOSITORY https://github.com/SerenityOS/serenity
)

# We need to manually populate the repository since we need to use the Lagom CMakeLists.txt.
FetchContent_GetProperties(serenity)
if(NOT serenity_POPULATED)
    FetchContent_Populate(serenity)
    add_subdirectory("${serenity_SOURCE_DIR}/Meta/Lagom" "${serenity_BINARY_DIR}" EXCLUDE_FROM_ALL)
    include_directories("${serenity_SOURCE_DIR}")
    include_directories("${serenity_SOURCE_DIR}/Userland/Libraries")
endif()

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(extdump)
add_subdirectory(LibExt4)
