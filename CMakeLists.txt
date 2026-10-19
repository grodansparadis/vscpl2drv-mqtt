cmake_minimum_required(VERSION 3.21)

project(vscpl2drv-mqtt VERSION 1.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)

# Derive the MSYS2 prefix from the selected native compiler instead of
# assuming a particular shell path or MSYS2 environment variable.
if (WIN32 AND MINGW)
    get_filename_component(VSCP_MINGW_TOOLCHAIN_BIN_DIR "${CMAKE_C_COMPILER}" DIRECTORY)
    get_filename_component(VSCP_MINGW_PREFIX "${VSCP_MINGW_TOOLCHAIN_BIN_DIR}/.." ABSOLUTE)
    set(VSCP_MINGW_BIN_DIR "" CACHE PATH
        "Directory containing MinGW runtime DLLs for install-time collection")
    if (NOT VSCP_MINGW_BIN_DIR)
        set(VSCP_MINGW_BIN_DIR "${VSCP_MINGW_TOOLCHAIN_BIN_DIR}")
    endif()
    list(PREPEND CMAKE_PREFIX_PATH "${VSCP_MINGW_PREFIX}")
endif()

# Make the unpacked nlohmann header visible.
include_directories(
    ${CMAKE_SOURCE_DIR}/third-party/json/include
    ${CMAKE_SOURCE_DIR}/third-party/Mustache
    ${CMAKE_SOURCE_DIR}/third-party/spdlog/include
    ${CMAKE_SOURCE_DIR}/third-party/fmt/include
)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/third-party/vscp/cmake/modules")

find_package(OpenSSL REQUIRED)
find_package(EXPAT REQUIRED)
find_package(Mosquitto REQUIRED)
find_package(Threads REQUIRED)

find_library(RT_LIBRARY rt)

add_library(vscpl2drv_mqtt SHARED
    linux/vscpl2drv_mqtt.cpp
    common/mqttobj.cpp
    third-party/vscp/src/vscp/common/vscpremotetcpif.cpp
    third-party/vscp/src/vscp/common/vscphelper.cpp
    third-party/vscp/src/vscp/common/vscpdatetime.cpp
    third-party/vscp/src/vscp/common/guid.cpp
    third-party/vscp/src/vscp/common/hlo.cpp
    third-party/vscp/src/common/sockettcp.c
    third-party/vscp/src/common/vscp-aes.c
    third-party/vscp/src/common/crc.c
    third-party/vscp/src/common/crc8.c
    third-party/vscp/src/common/vscpbase64.c
    third-party/vscp/src/common/vscpmd5.c
)

target_include_directories(vscpl2drv_mqtt PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/linux
    ${EXPAT_INCLUDE_DIRS}
    ${MOSQUITTO_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/third-party/vscp/src/common
    ${CMAKE_SOURCE_DIR}/third-party/vscp/src/vscp/common
)

target_compile_definitions(vscpl2drv_mqtt PRIVATE
    CBC
    MAJOR_VERSION=${PROJECT_VERSION_MAJOR}
    MINOR_VERSION=${PROJECT_VERSION_MINOR}
    RELEASE_VERSION=${PROJECT_VERSION_PATCH}
    BUILD_VERSION=0
    FMT_HEADER_ONLY
    OPENSSL_API_1_1
    SPDLOG_FMT_EXTERNAL
    _REENTRANT
)

if (WIN32)
    target_compile_definitions(vscpl2drv_mqtt PRIVATE WIN32)
    target_include_directories(vscpl2drv_mqtt PRIVATE
        ${CMAKE_SOURCE_DIR}/compat
        ${CMAKE_SOURCE_DIR}/third-party/vscp/src/vscp/daemon
    )
    if (MINGW)
        target_compile_options(vscpl2drv_mqtt PRIVATE
            -include "${CMAKE_SOURCE_DIR}/compat/mingw-preinclude.h"
        )
        set_source_files_properties(
            third-party/vscp/src/vscp/common/vscphelper.cpp
            PROPERTIES COMPILE_OPTIONS
                "-include;${CMAKE_SOURCE_DIR}/compat/mingw-vscphelper-preinclude.h"
        )
    endif()
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(vscpl2drv_mqtt PRIVATE __LINUX__)
endif()

target_link_libraries(vscpl2drv_mqtt PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${EXPAT_LIBRARIES}
    ${MOSQUITTO_LIBRARIES}
    Threads::Threads
)

if (WIN32)
    target_link_libraries(vscpl2drv_mqtt PRIVATE ws2_32 iphlpapi)
elseif (UNIX AND NOT APPLE)
    target_link_libraries(vscpl2drv_mqtt PRIVATE m dl)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND RT_LIBRARY)
    target_link_libraries(vscpl2drv_mqtt PRIVATE ${RT_LIBRARY})
endif()

set_target_properties(vscpl2drv_mqtt PROPERTIES
    OUTPUT_NAME vscpl2drv-mqtt
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

if (WIN32)
    set_target_properties(vscpl2drv_mqtt PROPERTIES PREFIX "")
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(vscpl2drv_mqtt_test linux/test.cpp)
    target_include_directories(vscpl2drv_mqtt_test PRIVATE
        ${CMAKE_SOURCE_DIR}/linux
    )
endif()

enable_testing()
add_executable(vscpl2drv_mqtt_semaphore_test ci/check-semaphore.cpp)
target_include_directories(vscpl2drv_mqtt_semaphore_test PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/third-party/vscp/src/vscp/common
    ${CMAKE_SOURCE_DIR}/third-party/vscp/src/common
)
target_link_libraries(vscpl2drv_mqtt_semaphore_test PRIVATE Threads::Threads)
if (WIN32)
    target_compile_definitions(vscpl2drv_mqtt_semaphore_test PRIVATE WIN32)
    target_include_directories(vscpl2drv_mqtt_semaphore_test PRIVATE
        ${CMAKE_SOURCE_DIR}/compat
        ${CMAKE_SOURCE_DIR}/third-party/vscp/src/vscp/daemon
    )
    if (MINGW)
        target_compile_options(vscpl2drv_mqtt_semaphore_test PRIVATE
            -include "${CMAKE_SOURCE_DIR}/compat/mingw-preinclude.h"
        )
    endif()
endif()
add_test(NAME driver-semaphore COMMAND vscpl2drv_mqtt_semaphore_test)
set_tests_properties(driver-semaphore PROPERTIES TIMEOUT 20)

if (WIN32)
    if (MINGW)
        install(TARGETS vscpl2drv_mqtt
            RUNTIME_DEPENDENCY_SET vscpl2drv_mqtt_runtime_dependencies
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
        install(RUNTIME_DEPENDENCY_SET vscpl2drv_mqtt_runtime_dependencies
            PRE_EXCLUDE_REGEXES "api-ms-" "ext-ms-"
            POST_EXCLUDE_REGEXES ".*[Ww]indows[/\\\\].*"
            DIRECTORIES "${VSCP_MINGW_BIN_DIR}"
        )
    else()
        install(TARGETS vscpl2drv_mqtt
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
else()
    install(TARGETS vscpl2drv_mqtt
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
