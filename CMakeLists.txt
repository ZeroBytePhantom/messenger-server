cmake_minimum_required(VERSION 3.28.3)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

project(messenger-server VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# === Dependencies ===
find_package(Boost 1.70 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

find_package(SQLite3 QUIET)
if(NOT SQLite3_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SQLITE3 REQUIRED sqlite3)
else()
    set(SQLITE3_LIBRARIES SQLite::SQLite3)
endif()

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
    FetchContent_MakeAvailable(json)
endif()

# BlueZ — optional
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(BLUEZ bluez)
endif()
if(BLUEZ_FOUND)
    add_compile_definitions(HAS_BLUETOOTH=1)
else()
    add_compile_definitions(HAS_BLUETOOTH=0)
endif()

# === Sources ===
set(SOURCES
        src/main.cpp
        src/core.cpp
        src/crypto.cpp
        src/database.cpp
        src/protocol.cpp
        src/transport.cpp
)

set(HEADERS
        src/core.h
        src/crypto.h
        src/database.h
        src/protocol.h
        src/transport.h
        src/types.h
)

add_executable(messenger-server ${SOURCES} ${HEADERS})

target_include_directories(messenger-server PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${SQLITE3_INCLUDE_DIRS}
)

if(BLUEZ_FOUND)
    target_include_directories(messenger-server PRIVATE ${BLUEZ_INCLUDE_DIRS})
endif()

target_link_libraries(messenger-server PRIVATE
        Boost::boost
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        ${SQLITE3_LIBRARIES}
        nlohmann_json::nlohmann_json
        pthread
)

if(BLUEZ_FOUND)
    target_link_libraries(messenger-server PRIVATE ${BLUEZ_LIBRARIES})
endif()

# === Copy runtime files ===
configure_file(${CMAKE_SOURCE_DIR}/config.json ${CMAKE_BINARY_DIR}/config.json COPYONLY)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/db)
configure_file(${CMAKE_SOURCE_DIR}/db/init.sql ${CMAKE_BINARY_DIR}/db/init.sql COPYONLY)