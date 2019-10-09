#!/bin/bash

# Warning!
# Do not run this script if you don't know what you do!

# General common files
cd _vscp_common_general
cp ${VSCP_PATH}/src/common/dllist.c .
cp ${VSCP_PATH}/src/common/dllist.h .
cp ${VSCP_PATH}/src/common/crc.h .
cp ${VSCP_PATH}/src/common/crc.c .
cp ${VSCP_PATH}/src/common/crc8.h .
cp ${VSCP_PATH}/src/common/crc8.c .
cp ${VSCP_PATH}/src/common/sockettcp.h .
cp ${VSCP_PATH}/src/common/sockettcp.c .
cp ${VSCP_PATH}/src/common/vscpmd5.h .
cp ${VSCP_PATH}/src/common/vscpmd5.c .
cp ${VSCP_PATH}/src/common/fastpbkdf2.h .
cp ${VSCP_PATH}/src/common/fastpbkdf2.c .
cp ${VSCP_PATH}/src/common/vscpbase64.h .
cp ${VSCP_PATH}/src/common/vscpbase64.c .
cp ${VSCP_PATH}/src/common/vscp_aes.h .
cp ${VSCP_PATH}/src/common/vscp_aes.c .
cp ${VSCP_PATH}/src/common/json.hpp .
cp -r ${VSCP_PATH}/src/common/nlohmann/ .
cd ..
# VSCP Common files
cd _vscp_common
cp ${VSCP_PATH}/src/vscp/common/version.h .
cp ${VSCP_PATH}/src/vscp/common/canal.h .
cp ${VSCP_PATH}/src/vscp/common/canal_macro.h .
cp ${VSCP_PATH}/src/vscp/common/vscp.h .
cp ${VSCP_PATH}/src/vscp/common/vscp_class.h .
cp ${VSCP_PATH}/src/vscp/common/vscp_type.h .
cp ${VSCP_PATH}/src/vscp/common/guid.cpp .
cp ${VSCP_PATH}/src/vscp/common/guid.h .
cp ${VSCP_PATH}/src/vscp/common/vscpremotetcpif.cpp .
cp ${VSCP_PATH}/src/vscp/common/vscpremotetcpif.h .
cp ${VSCP_PATH}/src/vscp/common/vscphelper.cpp .
cp ${VSCP_PATH}/src/vscp/common/vscphelper.h .
cp ${VSCP_PATH}/src/vscp/common/vscpdatetime.cpp .
cp ${VSCP_PATH}/src/vscp/common/vscpdatetime.h .
cp ${VSCP_PATH}/src/vscp/common/mdf.h .
cd ..