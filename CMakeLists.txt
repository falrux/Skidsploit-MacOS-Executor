cmake_minimum_required(VERSION 3.25)
project(skidsploit)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0")
set(CMAKE_OSX_ARCHITECTURES "arm64")

set(CMAKE_CXX_FLAGS "-stdlib=libc++ -fvisibility=hidden -fvisibility-inlines-hidden")
set(CMAKE_SHARED_LINKER_FLAGS "-dynamiclib -Wl,-x -Wl,-S")
set(CMAKE_OBJCXX_FLAGS "${CMAKE_CXX_FLAGS}")

set(DEPS "${CMAKE_SOURCE_DIR}/dependencies")

add_library(skidsploit SHARED main.cpp)
set_source_files_properties(main.cpp PROPERTIES COMPILE_FLAGS "-x objective-c++")

target_include_directories(skidsploit PRIVATE
    ${DEPS}/alexsploit
    ${DEPS}/luau/Compiler/include
    ${DEPS}/luau/Ast/include
    ${DEPS}/luau/Common/include
    ${DEPS}/luau/VM/include
    ${DEPS}/luau/VM/src
    ${DEPS}/tinyhook/include
)

find_package(ZLIB REQUIRED)

target_link_libraries(skidsploit PRIVATE
    ${DEPS}/tinyhook/libtinyhook.a
    ${DEPS}/libs/libLuau.VM.a
    ${DEPS}/libs/libLuau.Compiler.a
    ${DEPS}/libs/libLuau.Ast.a
    ${DEPS}/libs/libLuau.Common.a
    ZLIB::ZLIB
    "-lobjc"
)

set_target_properties(skidsploit PROPERTIES
    OUTPUT_NAME "skidsploit"
    SUFFIX ".dylib"
    PREFIX ""
)
