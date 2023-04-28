cmake_minimum_required(VERSION 3.25)
project(direct-syscall)
set(CMAKE_CXX_STANDARD 23)

file(GLOB_RECURSE SRC
        "src/*.cpp" ,
        "src/*.*" ,
        "src/*/*.*" ,
        "includes/*.*" ,
        "includes/*/*.*" ,
        )

add_executable(${PROJECT_NAME} ${SRC})
target_include_directories(${PROJECT_NAME} PUBLIC src)
target_include_directories(${PROJECT_NAME} PUBLIC includes)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO /NXCOMPAT:NO")