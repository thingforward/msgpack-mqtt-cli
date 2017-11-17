cmake_minimum_required(VERSION 3.5)
project(msgpack_mqtt_cli)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        lib/private_lib/mosquitto/mosquitto.h
        lib/private_lib/mpack/mpack-common.c
        lib/private_lib/mpack/mpack-common.h
        lib/private_lib/mpack/mpack-expect.c
        lib/private_lib/mpack/mpack-expect.h
        lib/private_lib/mpack/mpack-node.c
        lib/private_lib/mpack/mpack-node.h
        lib/private_lib/mpack/mpack-platform.c
        lib/private_lib/mpack/mpack-platform.h
        lib/private_lib/mpack/mpack-reader.c
        lib/private_lib/mpack/mpack-reader.h
        lib/private_lib/mpack/mpack-writer.c
        lib/private_lib/mpack/mpack-writer.h
        lib/private_lib/mpack/mpack.h
        lib/private_lib/rapidjson/error/en.h
        lib/private_lib/rapidjson/error/error.h
        lib/private_lib/rapidjson/internal/biginteger.h
        lib/private_lib/rapidjson/internal/diyfp.h
        lib/private_lib/rapidjson/internal/dtoa.h
        lib/private_lib/rapidjson/internal/ieee754.h
        lib/private_lib/rapidjson/internal/itoa.h
        lib/private_lib/rapidjson/internal/meta.h
        lib/private_lib/rapidjson/internal/pow10.h
        lib/private_lib/rapidjson/internal/regex.h
        lib/private_lib/rapidjson/internal/stack.h
        lib/private_lib/rapidjson/internal/strfunc.h
        lib/private_lib/rapidjson/internal/strtod.h
        lib/private_lib/rapidjson/internal/swap.h
        lib/private_lib/rapidjson/msinttypes/inttypes.h
        lib/private_lib/rapidjson/msinttypes/stdint.h
        lib/private_lib/rapidjson/allocators.h
        lib/private_lib/rapidjson/cursorstreamwrapper.h
        lib/private_lib/rapidjson/document.h
        lib/private_lib/rapidjson/encodedstream.h
        lib/private_lib/rapidjson/encodings.h
        lib/private_lib/rapidjson/filereadstream.h
        lib/private_lib/rapidjson/filewritestream.h
        lib/private_lib/rapidjson/fwd.h
        lib/private_lib/rapidjson/istreamwrapper.h
        lib/private_lib/rapidjson/memorybuffer.h
        lib/private_lib/rapidjson/memorystream.h
        lib/private_lib/rapidjson/ostreamwrapper.h
        lib/private_lib/rapidjson/pointer.h
        lib/private_lib/rapidjson/prettywriter.h
        lib/private_lib/rapidjson/rapidjson.h
        lib/private_lib/rapidjson/reader.h
        lib/private_lib/rapidjson/schema.h
        lib/private_lib/rapidjson/stream.h
        lib/private_lib/rapidjson/stringbuffer.h
        lib/private_lib/rapidjson/writer.h
        lib/private_lib/b64/cdecode.h
        lib/private_lib/b64/cencode.h
        lib/private_lib/b64/decode.h
        lib/private_lib/b64/encode.h
        lib/private_lib/b64/cdecode.c
        lib/private_lib/b64/cencode.c
        src/main.cpp)

include_directories(lib/private_lib/)

find_library(MOSQUITTO_LIB  mosquitto PATHS /usr/local/lib/)

add_executable(msgpack_mqtt_cli ${SOURCE_FILES})

target_link_libraries(msgpack_mqtt_cli "${MOSQUITTO_LIB}")
