# dependencies.cmake
#
# Third-party sources, fetched at configure time with FetchContent. They used
# to be git submodules in third-party/; each is pinned to the same commit.
# Every download is checked against its SHA256.
#
# To use a local checkout instead, set FETCHCONTENT_SOURCE_DIR_<NAME>, for
# example -DFETCHCONTENT_SOURCE_DIR_TP_VSCP=/path/to/vscp.
# FETCHCONTENT_FULLY_DISCONNECTED=ON reuses downloaded sources offline.
#
# Sets:
#   THIRD_PARTY_VSCP_DIR               grodansparadis/vscp
#   THIRD_PARTY_FMT_DIR                fmtlib/fmt
#   THIRD_PARTY_SPDLOG_DIR             gabime/spdlog
#   THIRD_PARTY_MUSTACHE_DIR           kainjow/Mustache
#   THIRD_PARTY_JSON_DIR               nlohmann/json
#

include_guard(GLOBAL)
include(FetchContent)

set(_tp_options)
if(NOT CMAKE_VERSION VERSION_LESS "3.18")
    # Populate the sources only; the projects are not added to the build.
    list(APPEND _tp_options SOURCE_SUBDIR "__sources_only__")
endif()
if(NOT CMAKE_VERSION VERSION_LESS "3.24")
    list(APPEND _tp_options DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
endif()

# grodansparadis/vscp @ d75d4f5c6c097a1dca841b63727c79c522b701ce (master)
FetchContent_Declare(
    tp_vscp
    URL https://codeload.github.com/grodansparadis/vscp/tar.gz/d75d4f5c6c097a1dca841b63727c79c522b701ce
    URL_HASH SHA256=709763c16c995b65787e72947f9c3f45a03a404c708286c7cad00b53dcaedbb5
    ${_tp_options}
)
# fmtlib/fmt @ 4f645a8d5d7aa6f8c5ba57e9af0396e4761d3f81
FetchContent_Declare(
    tp_fmt
    URL https://codeload.github.com/fmtlib/fmt/tar.gz/4f645a8d5d7aa6f8c5ba57e9af0396e4761d3f81
    URL_HASH SHA256=a1e982ddebd583614c5c41e1fee6e64e86eb74425fc3eba72a5548d9a34fbb74
    ${_tp_options}
)
# gabime/spdlog @ f5f173a1a57d0e2e0115f2ed71ee7ea316516853
FetchContent_Declare(
    tp_spdlog
    URL https://codeload.github.com/gabime/spdlog/tar.gz/f5f173a1a57d0e2e0115f2ed71ee7ea316516853
    URL_HASH SHA256=897a1f8d9b1978559fda73e08f94e30ea83c298e768625ae0ec2c3e2237ea952
    ${_tp_options}
)
# kainjow/Mustache @ 3f654942a70c46a775070d7a09ca7acfa3e205b7
FetchContent_Declare(
    tp_mustache
    URL https://codeload.github.com/kainjow/Mustache/tar.gz/3f654942a70c46a775070d7a09ca7acfa3e205b7
    URL_HASH SHA256=959b8fcaecc14fc0b6243c078a39fd13dab107dcda086ed2ca90e1a486269a36
    ${_tp_options}
)
# nlohmann/json @ 21af527e756435701f23e01aa8ea8dab6e050c90
FetchContent_Declare(
    tp_json
    URL https://codeload.github.com/nlohmann/json/tar.gz/21af527e756435701f23e01aa8ea8dab6e050c90
    URL_HASH SHA256=a4de85a312eb41a9a47b3756800f9c0dfec3afb3dec257fb1ee22c8f435245fe
    ${_tp_options}
)

set(_tp_names tp_vscp tp_fmt tp_spdlog tp_mustache tp_json)
if(CMAKE_VERSION VERSION_LESS "3.18")
    foreach(_tp IN LISTS _tp_names)
        FetchContent_GetProperties(${_tp})
        if(NOT ${_tp}_POPULATED)
            FetchContent_Populate(${_tp})
        endif()
    endforeach()
else()
    FetchContent_MakeAvailable(${_tp_names})
endif()

set(THIRD_PARTY_VSCP_DIR "${tp_vscp_SOURCE_DIR}")
set(THIRD_PARTY_FMT_DIR "${tp_fmt_SOURCE_DIR}")
set(THIRD_PARTY_SPDLOG_DIR "${tp_spdlog_SOURCE_DIR}")
set(THIRD_PARTY_MUSTACHE_DIR "${tp_mustache_SOURCE_DIR}")
set(THIRD_PARTY_JSON_DIR "${tp_json_SOURCE_DIR}")
