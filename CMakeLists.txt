cmake_minimum_required(VERSION 3.10)

project(vscpl2drv-mqtt VERSION 1.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)

# Make the repository root config.h and the unpacked nlohmann header visible.
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/compat/vscp
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

# mosquitto >= 2.1 transitively includes <cjson/cJSON.h>; find it so the
# compiler can locate the header on platforms (e.g. macOS/Homebrew) where
# it is installed outside the default system include paths.
find_package(cJSON CONFIG QUIET)
if(NOT cJSON_FOUND)
    find_path(CJSON_INCLUDE_DIR cjson/cJSON.h)
endif()

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
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/linux
    ${CMAKE_SOURCE_DIR}/third-party/vscp/src/common
    ${CMAKE_SOURCE_DIR}/third-party/vscp/src/vscp/common
    ${EXPAT_INCLUDE_DIR}
    ${EXPAT_INCLUDE_DIRS}
    ${MOSQUITTO_INCLUDE_DIR}
    ${MOSQUITTO_INCLUDE_DIRS}
    $<$<TARGET_EXISTS:cJSON::cJSON>:$<TARGET_PROPERTY:cJSON::cJSON,INTERFACE_INCLUDE_DIRECTORIES>>
    ${CJSON_INCLUDE_DIR}
)

target_compile_definitions(vscpl2drv_mqtt PRIVATE
    __LINUX__
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

target_link_libraries(vscpl2drv_mqtt PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${EXPAT_LIBRARIES}
    ${MOSQUITTO_LIBRARIES}
    Threads::Threads
    m
    dl
)

if (RT_LIBRARY)
    target_link_libraries(vscpl2drv_mqtt PRIVATE ${RT_LIBRARY})
endif()

set_target_properties(vscpl2drv_mqtt PROPERTIES
    OUTPUT_NAME vscpl2drv-mqtt
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

add_executable(vscpl2drv_mqtt_test linux/test.cpp)
target_include_directories(vscpl2drv_mqtt_test PRIVATE
    ${CMAKE_SOURCE_DIR}/linux
)

install(TARGETS vscpl2drv_mqtt
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
