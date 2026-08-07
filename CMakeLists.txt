cmake_minimum_required(VERSION 3.10)

project(vscpl2drv-mqtt VERSION 1.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(VSCP_THIRD_PARTY_DIR "${CMAKE_SOURCE_DIR}/third-party/vscp")
set(VSCP_COMMON_C_DIR "${VSCP_THIRD_PARTY_DIR}/src/common")
set(VSCP_COMMON_CPP_DIR "${VSCP_THIRD_PARTY_DIR}/src/vscp/common")

list(APPEND CMAKE_MODULE_PATH "${VSCP_THIRD_PARTY_DIR}/cmake/modules")

find_package(OpenSSL REQUIRED)
find_package(EXPAT REQUIRED)
find_package(Mosquitto REQUIRED)
find_package(Threads REQUIRED)

find_library(RT_LIBRARY rt)

configure_file(${CMAKE_SOURCE_DIR}/config.h ${CMAKE_BINARY_DIR}/config.h COPYONLY)

add_library(vscpl2drv_mqtt SHARED)
target_sources(vscpl2drv_mqtt PRIVATE
    linux/vscpl2drv_mqtt.cpp
    common/mqttobj.cpp
    ${VSCP_COMMON_CPP_DIR}/vscpremotetcpif.cpp
    ${VSCP_COMMON_CPP_DIR}/vscphelper.cpp
    ${VSCP_COMMON_CPP_DIR}/vscpdatetime.cpp
    ${VSCP_COMMON_CPP_DIR}/guid.cpp
    ${VSCP_COMMON_CPP_DIR}/hlo.cpp
    ${VSCP_COMMON_C_DIR}/sockettcp.c
    ${VSCP_COMMON_C_DIR}/vscp_aes.c
    ${VSCP_COMMON_C_DIR}/crc.c
    ${VSCP_COMMON_C_DIR}/crc8.c
    ${VSCP_COMMON_C_DIR}/vscpbase64.c
    ${VSCP_COMMON_C_DIR}/fastpbkdf2.c
    ${VSCP_COMMON_C_DIR}/vscpmd5.c
)

target_include_directories(vscpl2drv_mqtt PRIVATE
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/linux
    ${VSCP_COMMON_C_DIR}
    ${VSCP_COMMON_CPP_DIR}
    ${VSCP_COMMON_C_DIR}/third_party/nlohmann
    ${EXPAT_INCLUDE_DIRS}
    ${MOSQUITTO_INCLUDE_DIR}
)

target_compile_definitions(vscpl2drv_mqtt PRIVATE
    __LINUX__
    CBC
    MAJOR_VERSION=${PROJECT_VERSION_MAJOR}
    MINOR_VERSION=${PROJECT_VERSION_MINOR}
    RELEASE_VERSION=${PROJECT_VERSION_PATCH}
    BUILD_VERSION=0
    OPENSSL_API_1_1
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
