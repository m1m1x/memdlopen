cmake_minimum_required (VERSION 2.6)

project(memdlopen)

set(CMAKE_C_FLAGS "-g -Wall -pie -fPIC")

set(memdlopen_src
    ./main.c
    )

set(example_lib_src
    ./lib.c
    )


SET(BUILD_SHARED_LIBS on)
add_library(example ${example_lib_src})

add_executable(memdlopen ${memdlopen_src})
target_link_libraries(memdlopen dl)

