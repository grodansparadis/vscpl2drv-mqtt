// mqttobj.cpp: implementation of the CMQTT class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP Project (http://www.vscp.org)
//
// Copyright (C) 2000-2019 Ake Hedman,
// Grodans Paradis AB, <akhe@grodansparadis.com>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#include <list>
#include <map>
#include <string>

#include "limits.h"
#include "stdlib.h"
#include "syslog.h"
#include "unistd.h"
#include <ctype.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <expat.h>
#include <mosquitto.h>

#include <hlo.h>
#include <remotevariablecodes.h>
#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscphelper.h>
#include <vscpremotetcpif.h>

#include "mqttobj.h"

// Forward declarations
void*
workerThread(void* pData);

#define XML_BUFF_SIZE 30000

//////////////////////////////////////////////////////////////////////
// Cmqttobj
//

Cmqttobj::Cmqttobj()
{
    m_bRead      = false;
    m_bWrite     = false;
    m_bQuit      = false;
    m_bConnected = false;
    m_type       = VSCP_MQTT_TYPE_UNKNOWN;
    m_format     = VSCP_MQTT_FORMAT_STRING;

    // Params identifying this node
    m_index   = 0;
    m_zone    = 0;
    m_subzone = 0;

    m_sessionid = "";
    m_keepalive =
      60; // 0 = Don't keep alive, n = seconds to wait before reconnect
    m_qos = 0;

    // Encryption is disabled by default
    bEnableEncryption = false;

    // Simple
    m_bSimplify = false;
    m_host      = "127.0.0.1";
    m_port      = 1883;

    m_simple_vscpclass   = VSCP_CLASS1_MEASUREMENT;
    m_simple_vscptype    = -1; // Don't care
    m_simple_coding      = -1; // Don't care
    m_simple_unit        = -1; // Don't care
    m_simple_sensorindex = -1; // Don't care
    m_simple_index       = -1; // Don't care
    m_simple_zone        = -1; // Don't care
    m_simple_subzone     = -1; // Don't care

    // Initialize the mqtt library
    mosquitto_lib_init();

    vscp_clearVSCPFilter(&m_vscpfilterRx); // Accept all RX events
    vscp_clearVSCPFilter(&m_vscpfilterTx); // Accept all TX events

    sem_init(&m_semSendQueue, 0, 0);
    sem_init(&m_semReceiveQueue, 0, 0);

    pthread_mutex_init(&m_mutexSendQueue, NULL);
    pthread_mutex_init(&m_mutexReceiveQueue, NULL);
}

//////////////////////////////////////////////////////////////////////
// ~Cmqttobj
//

Cmqttobj::~Cmqttobj()
{
    close();

    pthread_mutex_destroy(&m_mutexSendQueue);
    pthread_mutex_destroy(&m_mutexReceiveQueue);

    sem_destroy(&m_semSendQueue);
    sem_destroy(&m_semReceiveQueue);

    mosquitto_lib_cleanup();
}

// ----------------------------------------------------------------------------

/* clang-format off */
/*
    XML Setup
    =========

    <?xml version = "1.0" encoding = "UTF-8" ?>
    <!-- Version 0.0.1    2019-11-29   -->
    <config debug="true|false"
            access="rw"
            keepalive="60"
            bencrypt="true|false"
            filter="incoming-filter"
            mask="incoming-mask"
            index="index identifying this driver"
            zone="zone identifying this driver"
            subzone="subzone identifying this driver"
            sessionid=""
            format="1"
            type="subscribe|publish"
            topic="mqtt path"
            prefix="mqtt part prefix"
            remote-host=""
            remote-port=""
            remote-user=""
            remote-password=""
            
            cafile="path to a file containing the PEM encoded trusted CA
               certificate files.  Either cafile or capath should be NULL."
            capath="path to a directory containing the PEM encoded trusted CA certificate
               files. Either cafile or capath should be NULL." 
            certfile="path to a file containing the PEM encoded certificate file for this 
               client.  If NULL, keyfile must also be NULL and no client certificate will be used."
            keyfile="path to a file containing
               the PEM encoded private key for this client.  If NULL, certfile
               must also be NULL and no client certificate will be used." 
            <simple
                enable="true|false" 
                vscpclass="" 
                vscptype="" 
                coding="" 
                unit="" sensoridenx=""
                index=""
                zone=""
                subzone="" />
    </config>
    "topic" is optional.
    Publish default to "/vscp/class/type/guid",
    subscribe defaults to "/vscp/ *".
    If given events are published as they are on topic.
    "prefix" can be set to add a path before the default
    topic or a set topic.

*/
/* clang-format on */

// ----------------------------------------------------------------------------

int depth_setup_parser = 0;

void
startSetupParser(void* data, const char* name, const char** attr)
{
    Cmqttobj* pObj = (Cmqttobj*)data;
    if (NULL == pObj)
        return;

    if ((0 == strcmp(name, "config")) && (0 == depth_setup_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "debug")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if (std::string::npos != attribute.find("TRUE")) {
                        pObj->m_bDebug = true;
                    } else {
                        pObj->m_bDebug = false;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "access")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if (std::string::npos != attribute.find("W")) {
                        pObj->m_bWrite = true;
                    } else {
                        pObj->m_bWrite = false;
                    }
                    if (std::string::npos != attribute.find("R")) {
                        pObj->m_bRead = true;
                    } else {
                        pObj->m_bRead = false;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "keepalive")) {
                if (!attribute.empty()) {
                    pObj->m_keepalive = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "qos")) {
                if (!attribute.empty()) {
                    pObj->m_qos = vscp_readStringValue(attribute);
                    if (pObj->m_qos > 2) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt]  Invalid QoS value [%d] - "
                               "Set to zero.",
                               pObj->m_qos);
                        pObj->m_qos = 0;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "index")) {
                if (!attribute.empty()) {
                    pObj->m_index = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "zone")) {
                if (!attribute.empty()) {
                    pObj->m_zone = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "subzone")) {
                if (!attribute.empty()) {
                    pObj->m_subzone = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "rxfilter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pObj->m_vscpfilterRx,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt]  Unable to read event "
                               "receive filter.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "rxmask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pObj->m_vscpfilterRx,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt]  Unable to read event "
                               "receive mask.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "txfilter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pObj->m_vscpfilterTx,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt]  Unable to read event "
                               "transmit filter.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "txmask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pObj->m_vscpfilterTx,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt]  Unable to read event "
                               "transmit mask.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "sessionid")) {
                if (!attribute.empty()) {
                    pObj->m_sessionid = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "type")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if (std::string::npos != attribute.find("SUBSCRIBE")) {
                        pObj->m_type = VSCP_MQTT_TYPE_SUBSCRIBE;
                    } else if (std::string::npos != attribute.find("PUBLISH")) {
                        pObj->m_type = VSCP_MQTT_TYPE_PUBLISH;
                    } else {
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt]  Type should be 'subscribe' "
                               "or 'publish' now =%s. Set to 'subscribe'",
                               attribute.c_str());
                        pObj->m_type = VSCP_MQTT_TYPE_SUBSCRIBE;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "format")) {
                if (!attribute.empty()) {
                    pObj->m_format = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "topic")) {
                if (!attribute.empty()) {
                    pObj->m_topic = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "prefix")) {
                if (!attribute.empty()) {
                    pObj->m_prefix = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "remote-host")) {
                if (!attribute.empty()) {
                    pObj->m_host = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "remote_port")) {
                if (!attribute.empty()) {
                    pObj->m_port = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "remote-user")) {
                if (!attribute.empty()) {
                    pObj->m_username = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "remote-password")) {
                if (!attribute.empty()) {
                    pObj->m_password = attribute;
                }
            }
        }
    } else if ((0 == strcmp(name, "simple")) && (1 == depth_setup_parser)) {
        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "enable")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if (std::string::npos != attribute.find("TRUE")) {
                        pObj->m_bSimplify = true;
                    } else {
                        pObj->m_bSimplify = false;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "vscpclass")) {
                if (!attribute.empty()) {
                    pObj->m_simple_vscpclass = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "vscptype")) {
                if (!attribute.empty()) {
                    pObj->m_simple_vscptype = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "coding")) {
                if (!attribute.empty()) {
                    pObj->m_simple_coding = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "unit")) {
                if (!attribute.empty()) {
                    pObj->m_simple_unit = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "sensorindex")) {
                if (!attribute.empty()) {
                    pObj->m_simple_sensorindex =
                      vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "index")) {
                if (!attribute.empty()) {
                    pObj->m_simple_index = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "zone")) {
                if (!attribute.empty()) {
                    pObj->m_simple_zone = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "subzone")) {
                if (!attribute.empty()) {
                    pObj->m_simple_subzone = vscp_readStringValue(attribute);
                }
            }
        }
    }

    depth_setup_parser++;
}

void
endSetupParser(void* data, const char* name)
{
    depth_setup_parser--;
}

// ----------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////
// open
//

bool
Cmqttobj::open(std::string& pathcfg, cguid& guid)
{
    // Set GUID
    m_guid = guid;

    // Save config path
    m_path = pathcfg;

    // Read configuration file
    if (!doLoadConfig()) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Failed to load configuration file [%s]",
               m_path.c_str());
    }

    int rv;
    if (MOSQ_ERR_SUCCESS != (rv = mosquitto_sub_topic_check(m_topic.c_str()))) {
        switch (rv) {

            case MOSQ_ERR_INVAL:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] The topic contains a + or a # that is "
                       "in an invalid position, or if it is too long.");
                return false;
                break;

            case MOSQ_ERR_MALFORMED_UTF8:
                syslog(LOG_ERR, "[vscpl2drv-mqtt] Topic is not valid UTF-8");
                return false;
                break;
        }
    }

    // start the workerthread
    if (pthread_create(&m_threadWork, NULL, workerThread, this)) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unable to start worker thread.");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
Cmqttobj::close(void)
{
    // Do nothing if already terminated
    if (m_bQuit)
        return;

    m_bQuit = true; // terminate the thread

    // Wait for workerthread to end
    int rv;
    if (0 != (rv = pthread_join(m_threadWork, NULL))) {
        switch (rv) {

            case EDEADLK:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] A deadlock was detected (e.g., two "
                       "threads tried to join with each other).");
                break;

            case EINVAL:
                syslog(
                  LOG_ERR,
                  "[vscpl2drv-mqtt] workerthread is not a joinable thread.");
                sleep(1); // Wait instead
                break;

            case ESRCH:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] No thread with the ID thread could be "
                       "found.");
                break;
        }
    }
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

bool
Cmqttobj::doLoadConfig(void)
{
    FILE* fp;

    fp = fopen(m_path.c_str(), "r");
    if (NULL == fp) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Failed to open configuration file [%s]",
               m_path.c_str());
        return false;
    }

    XML_Parser xmlParser = XML_ParserCreate("UTF-8");
    XML_SetUserData(xmlParser, this);
    XML_SetElementHandler(xmlParser, startSetupParser, endSetupParser);

    void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

    size_t file_size = 0;
    file_size        = fread(buf, sizeof(char), XML_BUFF_SIZE, fp);

    if (XML_STATUS_OK !=
        XML_ParseBuffer(xmlParser, file_size, file_size == 0)) {
        enum XML_Error errcode = XML_GetErrorCode(xmlParser);
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Failed parse XML setup [%s].",
               XML_ErrorString(errcode));
        XML_ParserFree(xmlParser);
        return false;
    }

    XML_ParserFree(xmlParser);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

bool
Cmqttobj::doSaveConfig(void)
{
    return true;
}

// ----------------------------------------------------------------------------

int depth_hlo_parser = 0;

void
startHLOParser(void* data, const char* name, const char** attr)
{
    CHLO* pObj = (CHLO*)data;
    if (NULL == pObj)
        return;

    if ((0 == strcmp(name, "vscp-cmd")) && (0 == depth_setup_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "op")) {
                if (!attribute.empty()) {
                    pObj->m_op = vscp_readStringValue(attribute);
                    vscp_makeUpper(attribute);
                    if (attribute == "VSCP-NOOP") {
                        pObj->m_op = HLO_OP_NOOP;
                    } else if (attribute == "VSCP-READVAR") {
                        pObj->m_op = HLO_OP_READ_VAR;
                    } else if (attribute == "VSCP-WRITEVAR") {
                        pObj->m_op = HLO_OP_WRITE_VAR;
                    } else if (attribute == "VSCP-LOAD") {
                        pObj->m_op = HLO_OP_LOAD;
                    } else if (attribute == "VSCP-SAVE") {
                        pObj->m_op = HLO_OP_SAVE;
                    } else {
                        pObj->m_op = HLO_OP_UNKNOWN;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "name")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    pObj->m_name = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "type")) {
                if (!attribute.empty()) {
                    pObj->m_varType = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "value")) {
                if (!attribute.empty()) {
                    if (vscp_base64_std_decode(attribute)) {
                        pObj->m_value = attribute;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "full")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if ("TRUE" == attribute) {
                        pObj->m_bFull = true;
                    } else {
                        pObj->m_bFull = false;
                    }
                }
            }
        }
    }

    depth_hlo_parser++;
}

void
endHLOParser(void* data, const char* name)
{
    depth_hlo_parser--;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// parseHLO
//

bool
Cmqttobj::parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo)
{
    // Check pointers
    if (NULL == inbuf) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-automation] HLO parser: HLO in-buffer pointer is NULL.");
        return false;
    }

    if (NULL == phlo) {
        syslog(LOG_ERR,
               "[vscpl2drv-automation] HLO parser: HLO obj pointer is NULL.");
        return false;
    }

    if (!size) {
        syslog(LOG_ERR,
               "[vscpl2drv-automation] HLO parser: HLO buffer size is zero.");
        return false;
    }

    XML_Parser xmlParser = XML_ParserCreate("UTF-8");
    XML_SetUserData(xmlParser, this);
    XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

    void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

    // Copy in the HLO object
    memcpy(buf, inbuf, size);

    if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
        syslog(LOG_ERR, "[vscpl2drv-automation] Failed parse XML setup.");
        XML_ParserFree(xmlParser);
        return false;
    }

    XML_ParserFree(xmlParser);

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

bool
Cmqttobj::handleHLO(vscpEvent* pEvent)
{
    char buf[512]; // Working buffer
    vscpEventEx ex;

    // Check pointers
    if (NULL == pEvent) {
        syslog(LOG_ERR,
               "[vscpl2drv-automation] HLO handler: NULL event pointer.");
        return false;
    }

    CHLO hlo;
    if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
        syslog(LOG_ERR, "[vscpl2drv-automation] Failed to parse HLO.");
        return false;
    }

    ex.obid      = 0;
    ex.head      = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS2_PROTOCOL;
    ex.vscp_type  = VSCP2_TYPE_PROTOCOL_HIGH_LEVEL_OBJECT;
    m_guid.writeGUID(ex.GUID);

    switch (hlo.m_op) {

        case HLO_OP_NOOP:
            // Send positive response
            sprintf(buf,
                    HLO_CMD_REPLY_TEMPLATE,
                    "noop",
                    "OK",
                    "NOOP commaned executed correctly.");

            memset(ex.data, 0, sizeof(ex.data));
            ex.sizeData = strlen(buf);
            memcpy(ex.data, buf, ex.sizeData);

            // Put event in receive queue
            return eventExToReceiveQueue(ex);

        case HLO_OP_READ_VAR:
            if ("SUNRISE" == hlo.m_name) {
                /*sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "sunrise",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_DATETIME,
                        vscp_convertToBase64(getSunriseTime().getISODateTime())
                          .c_str());*/
            } else {
                sprintf(buf,
                        HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                        hlo.m_name.c_str(),
                        ERR_VARIABLE_UNKNOWN,
                        vscp_convertToBase64(std::string("Unknown variable"))
                          .c_str());
            }
            break;

        case HLO_OP_WRITE_VAR:
            if ("SUNRISE" == hlo.m_name) {
                // Read Only variable
                sprintf(buf,
                        HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                        "sunrise",
                        VSCP_REMOTE_VARIABLE_CODE_BOOLEAN,
                        "Variable is read only.");
            } else {
                sprintf(buf,
                        HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                        hlo.m_name.c_str(),
                        1,
                        vscp_convertToBase64(std::string("Unknown variable"))
                          .c_str());
            }
            break;

        case HLO_OP_SAVE:
            doSaveConfig();
            break;

        case HLO_OP_LOAD:
            doLoadConfig();
            break;

        default:
            break;
    };

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// eventExToReceiveQueue
//

bool
Cmqttobj::eventExToReceiveQueue(vscpEventEx& ex)
{
    vscpEvent* pev = new vscpEvent();
    if (!vscp_convertEventExToEvent(pev, &ex)) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Failed to convert event from ex to ev.");
        vscp_deleteEvent(pev);
        return false;
    }
    if (NULL != pev) {
        if (vscp_doLevel2Filter(pev, &m_vscpfilterRx)) {
            pthread_mutex_lock(&m_mutexReceiveQueue);
            m_receiveList.push_back(pev);
            sem_post(&m_semReceiveQueue);
            pthread_mutex_unlock(&m_mutexReceiveQueue);
        } else {
            vscp_deleteEvent(pev);
        }
    } else {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unable to allocate event storage.");
    }
    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//

bool
Cmqttobj::addEvent2SendQueue(const vscpEvent* pEvent)
{
    pthread_mutex_lock(&m_mutexSendQueue);
    m_sendList.push_back((vscpEvent*)pEvent);
    sem_post(&m_semSendQueue);
    pthread_mutex_unlock(&m_mutexSendQueue);
    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2ReceiveQueue
//

bool
Cmqttobj::addEvent2ReceiveQueue(const vscpEvent* pEvent)
{
    pthread_mutex_lock(&m_mutexReceiveQueue);
    m_receiveList.push_back((vscpEvent*)pEvent);
    sem_post(&m_semReceiveQueue);
    pthread_mutex_unlock(&m_mutexReceiveQueue);
    return true;
}

//////////////////////////////////////////////////////////////////////
// Connect callback
//

void
on_connect(struct mosquitto* mosq, void* obj, int rc, int flags)
{
    // We have a connect with a remote server
    if (NULL == obj) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add connect event due to missing "
               "object pointer.");
        return;
    }

    Cmqttobj* pObj = (Cmqttobj*)obj;

    vscpEvent* pEvent = new vscpEvent;
    if (NULL == pEvent) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add connect event due to memory "
               "problem (event).");
        return;
    }

    pEvent->pdata = new uint8_t[3];
    if (NULL == pEvent->pdata) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add connect event due to memory "
               "problem (data).");
        vscp_deleteEvent_v2(&pEvent);
        return;
    }

    pEvent->head      = VSCP_HEADER16_DUMB;
    pEvent->obid      = 0;
    pEvent->timestamp = 0; // Let i&f set timestamp
    vscp_setEventToNow(pEvent);
    pEvent->vscp_class = VSCP_CLASS1_INFORMATION;
    pEvent->vscp_type  = VSCP_TYPE_INFORMATION_CONNECT;
    pEvent->sizeData   = 3;
    pEvent->pdata[0]   = pObj->m_index;
    pEvent->pdata[1]   = pObj->m_zone;
    pEvent->pdata[2]   = pObj->m_subzone;
    pObj->m_guid.writeGUID(pEvent->GUID);

    if (!pObj->addEvent2ReceiveQueue(pEvent)) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unable to add connect event.");
        vscp_deleteEvent_v2(&pEvent);
    }
}

//////////////////////////////////////////////////////////////////////
// Disconnect callback
//

void
on_disconnect(struct mosquitto* mosq, void* obj, int rc)
{
    if (0 == rc) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Client disconnect.");
    } else {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unexpected disconnect. [rc=%d]", rc);
    }

    // We have a connect with a remote server
    if (NULL == obj) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add disconnect event due to missing "
               "object pointer.");
        return;
    }

    Cmqttobj* pObj = (Cmqttobj*)obj;

    vscpEvent* pEvent = new vscpEvent;
    if (NULL == pEvent) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add disconnect event due to memory "
               "problem (event).");
        return;
    }

    pEvent->pdata = new uint8_t[3];
    if (NULL == pEvent->pdata) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add disconnect event due to memory "
               "problem (data).");
        vscp_deleteEvent_v2(&pEvent);
        return;
    }

    pEvent->head      = VSCP_HEADER16_DUMB;
    pEvent->obid      = 0;
    pEvent->timestamp = 0; // Let i&f set timestamp
    vscp_setEventToNow(pEvent);
    pEvent->vscp_class = VSCP_CLASS1_INFORMATION;
    pEvent->vscp_type  = VSCP_TYPE_INFORMATION_DISCONNECT;
    pEvent->sizeData   = 3;
    pEvent->pdata[0]   = pObj->m_index;
    pEvent->pdata[1]   = pObj->m_zone;
    pEvent->pdata[2]   = pObj->m_subzone;
    pObj->m_guid.writeGUID(pEvent->GUID);

    if (!pObj->addEvent2ReceiveQueue(pEvent)) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unable to add connect event.");
        vscp_deleteEvent_v2(&pEvent);
    }
}

//////////////////////////////////////////////////////////////////////
// Publish callback
//

void
on_publish(struct mosquitto* mosq, void* obj, int mid)
{
    // We have a connect with a remote server
    if (NULL == obj) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-mqtt] Unable to add publish success event due to missing "
          "object pointer.");
        return;
    }

    Cmqttobj* pObj = (Cmqttobj*)obj;

    vscpEvent* pEvent = new vscpEvent;
    if (NULL == pEvent) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-mqtt] Unable to add publish success event due to memory "
          "problem (event).");
        return;
    }

    pEvent->pdata = new uint8_t[4];
    if (NULL == pEvent->pdata) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-mqtt] Unable to add publish success event due to memory "
          "problem (data).");
        vscp_deleteEvent_v2(&pEvent);
        return;
    }

    pEvent->head      = VSCP_HEADER16_DUMB;
    pEvent->obid      = 0;
    pEvent->timestamp = 0; // Let i&f set timestamp
    vscp_setEventToNow(pEvent);
    pEvent->vscp_class = VSCP_CLASS1_ERROR;
    pEvent->vscp_type  = VSCP_TYPE_ERROR_SUCCESS;
    pEvent->sizeData   = 4;
    pEvent->pdata[0]   = pObj->m_index;
    pEvent->pdata[1]   = pObj->m_zone;
    pEvent->pdata[2]   = pObj->m_subzone;
    pEvent->pdata[3]   = ERROR_CODE_SUCCESS_PUBLISH; // Publish
    pObj->m_guid.writeGUID(pEvent->GUID);

    if (!pObj->addEvent2ReceiveQueue(pEvent)) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unable to add connect event.");
        vscp_deleteEvent_v2(&pEvent);
    }
}

//////////////////////////////////////////////////////////////////////
// Subscribe callback
//

void
on_subscribe(struct mosquitto* mosq,
             void* obj,
             int mid,
             int qos_count,
             const int* granted_qos)
{
    // We have a connect with a remote server
    if (NULL == obj) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add subscribe success event due to "
               "missing object pointer.");
        return;
    }

    Cmqttobj* pObj = (Cmqttobj*)obj;

    vscpEvent* pEvent = new vscpEvent;
    if (NULL == pEvent) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add subscribe success event due to "
               "memory problem (event).");
        return;
    }

    pEvent->pdata = new uint8_t[4];
    if (NULL == pEvent->pdata) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add subscribe success event due to "
               "memory problem (data).");
        vscp_deleteEvent_v2(&pEvent);
        return;
    }

    pEvent->head      = VSCP_HEADER16_DUMB;
    pEvent->obid      = 0;
    pEvent->timestamp = 0; // Let i&f set timestamp
    vscp_setEventToNow(pEvent);
    pEvent->vscp_class = VSCP_CLASS1_ERROR;
    pEvent->vscp_type  = VSCP_TYPE_ERROR_SUCCESS;
    pEvent->sizeData   = 4;
    pEvent->pdata[0]   = pObj->m_index;
    pEvent->pdata[1]   = pObj->m_zone;
    pEvent->pdata[2]   = pObj->m_subzone;
    pEvent->pdata[3]   = ERROR_CODE_SUCCESS_SUBSCRIBE; // Subscribe
    pObj->m_guid.writeGUID(pEvent->GUID);

    if (!pObj->addEvent2ReceiveQueue(pEvent)) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unable to add connect event.");
        vscp_deleteEvent_v2(&pEvent);
    }
}

//////////////////////////////////////////////////////////////////////
// Unsubscribe callback
//

void
on_unsubscribe(struct mosquitto* mosq, void* obj, int mid)
{
    // We have a connect with a remote server
    if (NULL == obj) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-mqtt] Unable to add unsubscribe success event due to "
          "missing object pointer.");
        return;
    }

    Cmqttobj* pObj = (Cmqttobj*)obj;

    vscpEvent* pEvent = new vscpEvent;
    if (NULL == pEvent) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-mqtt] Unable to add unsubscribe success event due to "
          "memory problem (event).");
        return;
    }

    pEvent->pdata = new uint8_t[4];
    if (NULL == pEvent->pdata) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-mqtt] Unable to add unsubscribe success event due to "
          "memory problem (data).");
        vscp_deleteEvent_v2(&pEvent);
        return;
    }

    pEvent->head      = VSCP_HEADER16_DUMB;
    pEvent->obid      = 0;
    pEvent->timestamp = 0; // Let i&f set timestamp
    vscp_setEventToNow(pEvent);
    pEvent->vscp_class = VSCP_CLASS1_ERROR;
    pEvent->vscp_type  = VSCP_TYPE_ERROR_SUCCESS;
    pEvent->sizeData   = 4;
    pEvent->pdata[0]   = pObj->m_index;
    pEvent->pdata[1]   = pObj->m_zone;
    pEvent->pdata[2]   = pObj->m_subzone;
    pEvent->pdata[3]   = ERROR_CODE_SUCCESS_UNSUBSCRIBE; // Unsubscribe
    pObj->m_guid.writeGUID(pEvent->GUID);

    if (!pObj->addEvent2ReceiveQueue(pEvent)) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unable to add connect event.");
        vscp_deleteEvent_v2(&pEvent);
    }
}

//////////////////////////////////////////////////////////////////////
// Message callback
//

void
on_message(struct mosquitto* mosq,
           void* obj,
           const struct mosquitto_message* message)
{
    std::string strMsg((const char*)message->payload, message->payloadlen);
    std::string strTopic = message->topic;

    // We have a connect with a remote server
    if (NULL == obj) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add incoming event due to "
               "missing object pointer.");
        return;
    }

    Cmqttobj* pObj = (Cmqttobj*)obj;

    vscpEvent* pEvent = new vscpEvent;
    if (NULL == pEvent) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Unable to add incoming event due to "
               "memory problem (event).");
        return;
    }

    if (pObj->m_bDebug) {
        syslog(LOG_ERR,
               "[vscpl2drv-mqtt] Event received topic=%s [%s].",
               strTopic.c_str(),
               strMsg.c_str());
    }

    if (pObj->m_bSimplify) {

        int offset = 0;
        uint16_t size;
        double value = std::stod(strMsg);
        uint8_t buf[VSCP_MAX_DATA];

        pEvent->head      = VSCP_HEADER16_DUMB;
        pEvent->obid      = 0;
        pEvent->timestamp = 0; // Let i&f set timestamp
        vscp_setEventToNow(pEvent);
        pObj->m_guid.writeGUID(pEvent->GUID);
        pEvent->vscp_class = pObj->m_simple_vscpclass;
        pEvent->vscp_type  = pObj->m_simple_vscptype;

        switch (pObj->m_simple_vscpclass) {

            case VSCP_CLASS1_MEASUREMENT:
            case VSCP_CLASS1_DATA:
                if (!vscp_convertFloatToNormalizedEventData(
                      buf,
                      &size,
                      value,
                      pObj->m_simple_unit,
                      pObj->m_simple_sensorindex)) {
                    syslog(
                      LOG_ERR,
                      "[vscpl2drv-mqtt] Failed to make event from measurement "
                      "value topic=%s [%s].",
                      strTopic.c_str(),
                      strMsg.c_str());
                    vscp_deleteEvent_v2(&pEvent);
                    return;
                }

                // Allocate data space
                pEvent->sizeData = size;
                pEvent->pdata    = new uint8_t[size];
                if (NULL == pEvent->pdata) {
                    syslog(
                      LOG_ERR,
                      "[vscpl2drv-mqtt] Unable to create data space due to "
                      "memory problem (data).");
                    vscp_deleteEvent_v2(&pEvent);
                    return;
                }

                memcpy(pEvent->pdata, buf, size);
                break;

            case VSCP_CLASS1_MEASUREMENT32:
            case VSCP_CLASS1_MEASUREMENT64:
                offset = 0;
                if (!vscp_convertFloatToNormalizedEventData(
                      buf,
                      &size,
                      value,
                      pObj->m_simple_unit,
                      pObj->m_simple_sensorindex)) {
                    syslog(
                      LOG_ERR,
                      "[vscpl2drv-mqtt] Failed to make event from measurement "
                      "value topic=%s [%s].",
                      strTopic.c_str(),
                      strMsg.c_str());
                    vscp_deleteEvent_v2(&pEvent);
                    return;
                }

                // Allocate data space
                pEvent->sizeData = size;
                pEvent->pdata    = new uint8_t[size];
                if (NULL == pEvent->pdata) {
                    syslog(
                      LOG_ERR,
                      "[vscpl2drv-mqtt] Unable to create data space due to "
                      "memory problem (data).");
                    vscp_deleteEvent_v2(&pEvent);
                    return;
                }

                memcpy(pEvent->pdata, buf, size);
                break;

            case VSCP_CLASS1_MEASUREZONE:
            case VSCP_CLASS1_SETVALUEZONE:
                if (!vscp_convertFloatToNormalizedEventData(
                      buf + 3,
                      &size,
                      value,
                      pObj->m_simple_unit,
                      pObj->m_simple_sensorindex)) {
                    syslog(
                      LOG_ERR,
                      "[vscpl2drv-mqtt] Failed to make event from measurement "
                      "value topic=%s [%s].",
                      strTopic.c_str(),
                      strMsg.c_str());
                    vscp_deleteEvent_v2(&pEvent);
                    return;
                }

                buf[0] = pObj->m_simple_index;
                buf[1] = pObj->m_simple_zone;
                buf[2] = pObj->m_simple_subzone;

                // Allocate data space
                pEvent->pdata = new uint8_t[size + offset];
                if (NULL == pEvent->pdata) {
                    syslog(
                      LOG_ERR,
                      "[vscpl2drv-mqtt] Unable to create data space due to "
                      "memory problem (data).");
                    vscp_deleteEvent_v2(&pEvent);
                    return;
                }

                memcpy(pEvent->pdata, buf, size + offset);
                break;

            case VSCP_CLASS2_MEASUREMENT_STR:
                if (!vscp_makeLevel2StringMeasurementEvent(
                      pEvent,
                      pEvent->vscp_type,
                      value,
                      pObj->m_simple_unit,
                      pObj->m_simple_sensorindex,
                      pObj->m_simple_zone,
                      pObj->m_simple_subzone)) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Failed to make level II string "
                           "event from measurement "
                           "value topic=%s [%s].",
                           strTopic.c_str(),
                           strMsg.c_str());
                    vscp_deleteEvent_v2(&pEvent);
                    return;
                }
                break;

            case VSCP_CLASS2_MEASUREMENT_FLOAT:
                if (!vscp_makeLevel2FloatMeasurementEvent(
                      pEvent,
                      pEvent->vscp_type,
                      value,
                      pObj->m_simple_unit,
                      pObj->m_simple_sensorindex,
                      pObj->m_simple_zone,
                      pObj->m_simple_subzone)) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Failed to make level II float "
                           "event from measurement "
                           "value topic=%s [%s].",
                           strTopic.c_str(),
                           strMsg.c_str());
                    vscp_deleteEvent_v2(&pEvent);
                    return;
                }
                break;

            default:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] Non supported simple measurement "
                       "event %d topic=%s [%s].",
                       pObj->m_simple_vscpclass,
                       strTopic.c_str(),
                       strMsg.c_str());
                vscp_deleteEvent_v2(&pEvent);
                return;
        }

    } else {
        switch (pObj->m_format) {

            case VSCP_MQTT_FORMAT_STRING:
                if (!vscp_convertStringToEvent(pEvent, strMsg)) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Failed to convert event on string "
                           "form [%s].",
                           strMsg.c_str());
                    return;
                }
                break;

            case VSCP_MQTT_FORMAT_XML:
                if (!vscp_convertXMLToEvent(pEvent, strMsg)) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Failed to convert event on XML "
                           "form [%s].",
                           strMsg.c_str());
                    return;
                }
                break;

            case VSCP_MQTT_FORMAT_JSON:
                if (!vscp_convertJSONToEvent(pEvent, strMsg)) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Failed to convert event on JSON "
                           "form [%s].",
                           strMsg.c_str());
                    return;
                }
                break;

            default:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] Unable to add incoming event: Unknown "
                       "message format.");
                vscp_deleteEvent_v2(&pEvent);
                return;
        }
    }

    if (!pObj->addEvent2ReceiveQueue(pEvent)) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Unable to add incoming event.");
        vscp_deleteEvent_v2(&pEvent);
    }
}

//////////////////////////////////////////////////////////////////////
// Login callback
//

void
on_log(struct mosquitto* mosq, void* obj, int level, const char* str)
{}

//////////////////////////////////////////////////////////////////////
// Workerthread
//

void*
workerThread(void* pData)
{
    int rv;
    struct mosquitto* mosq;
    uint32_t timestamp = vscp_getMsTimeStamp();

    if (NULL == pData) {
        syslog(LOG_ERR, "[vscpl2drv-mqtt] Missing thread object!");
        return NULL;
    }

    Cmqttobj* pObj = (Cmqttobj*)pData;

    char buf[80];
    char* p = NULL;
    if (pObj->m_sessionid.length()) {
        strncpy(buf,
                pObj->m_sessionid.c_str(),
                MIN(sizeof(buf) - 2, pObj->m_sessionid.length()));
        p = buf;
    }

    if (NULL == (mosq = mosquitto_new(p, true, pObj))) {
        switch (errno) {

            case ENOMEM:
                syslog(LOG_ERR, "[vscpl2drv-mqtt] Out of memory. Terminating");
                return NULL;
                break;

            case EINVAL:
                syslog(
                  LOG_ERR,
                  "[vscpl2drv-mqtt] Invalid input parameters. Terminating.");
                return NULL;
                break;
        }
    }

    // Register callbacks
    mosquitto_connect_with_flags_callback_set(mosq, on_connect);
    mosquitto_disconnect_callback_set(mosq, on_disconnect);
    mosquitto_publish_callback_set(mosq, on_publish);
    mosquitto_message_callback_set(mosq, on_message);
    mosquitto_subscribe_callback_set(mosq, on_subscribe);
    mosquitto_unsubscribe_callback_set(mosq, on_unsubscribe);
    mosquitto_log_callback_set(mosq, on_log);

    if (MOSQ_ERR_SUCCESS != (rv = mosquitto_connect(mosq,
                                                    pObj->m_host.c_str(),
                                                    pObj->m_port,
                                                    pObj->m_keepalive))) {
        switch (rv) {

            case MOSQ_ERR_INVAL:
                syslog(
                  LOG_ERR,
                  "[vscpl2drv-mqtt] Invalid input parameters. Terminating");
                mosquitto_destroy(mosq);
                return NULL;

            case MOSQ_ERR_ERRNO:
                char errbuf[128];
                syslog(
                  LOG_ERR,
                  "[vscpl2drv-mqtt] A system call returned an error. [%d %s] "
                  "Terminating",
                  errno,
                  strerror_r(errno, errbuf, sizeof(errbuf)));
                mosquitto_destroy(mosq);
                return NULL;
        }
    }

    if (VSCP_MQTT_TYPE_SUBSCRIBE == pObj->m_type) {

        // * * * subscribe * * *

        std::string topic = pObj->m_prefix + pObj->m_topic;
        if (!topic.length()) {
            topic = "/vscp/#";
        }

        if (MOSQ_ERR_SUCCESS !=
            (rv =
               mosquitto_subscribe(mosq, NULL, topic.c_str(), pObj->m_qos))) {

            switch (rv) {
                case MOSQ_ERR_INVAL:

                    break;

                case MOSQ_ERR_NOMEM:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] An out of memory condition "
                           "occurred..");
                    break;

                case MOSQ_ERR_NO_CONN:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] The client isn’t connected "
                           "to a broker.");
                    break;

                case MOSQ_ERR_MALFORMED_UTF8:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] The topic is not "
                           "valid UTF-8");
                    break;

                case MOSQ_ERR_OVERSIZE_PACKET:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] The resulting packet would "
                           "be larger than supported by the broker.");
                    break;
            }

            return NULL;
        }

        while (!pObj->m_bQuit) {

            // Send heartbeat if it's time for that
            if ((vscp_getMsTimeStamp() - timestamp) > 60000) {

                timestamp = vscp_getMsTimeStamp();

                vscpEvent* pEvent = new vscpEvent;
                if (NULL == pEvent) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Unable to add "
                           "incoming event due to "
                           "memory problem (event).");
                    return NULL;
                }

                pEvent->head      = VSCP_HEADER16_DUMB;
                pEvent->obid      = 0;
                pEvent->timestamp = 0; // Let i&f set timestamp
                vscp_setEventToNow(pEvent);
                pEvent->vscp_class = VSCP_CLASS1_INFORMATION;
                pEvent->vscp_type  = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT;
                pEvent->sizeData   = 3;
                pEvent->pdata      = new uint8_t[3];
                if (NULL == pEvent->pdata) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Out of memory problem when "
                           "sending heartbeat.");
                    pObj->m_bQuit = true;
                    continue;
                }
                pEvent->pdata[0] = pObj->m_index;
                pEvent->pdata[1] = pObj->m_zone;
                pEvent->pdata[2] = pObj->m_subzone;
                pObj->m_guid.writeGUID(pEvent->GUID);

                if (!pObj->addEvent2ReceiveQueue(pEvent)) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Unable to add "
                           "subscribe heatbeat "
                           "event.");
                    vscp_deleteEvent_v2(&pEvent);
                }
            }

            if (MOSQ_ERR_SUCCESS != (rv = mosquitto_loop(mosq, 100, 1))) {
                switch (rv) {
                    case MOSQ_ERR_INVAL:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] An input "
                               "parameters are "
                               "invalid.");
                        pObj->m_bQuit = true;
                        break;

                    case MOSQ_ERR_NOMEM:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] An out of memory "
                               "condition "
                               "occurred..");
                        pObj->m_bQuit = true;
                        break;

                    case MOSQ_ERR_NO_CONN:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] The client isn’t "
                               "connected "
                               "to a broker.");
                        pObj->m_bQuit = true;
                        break;

                    case MOSQ_ERR_CONN_LOST:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] The connection to the "
                               "broker was lost.");
                        break;

                    case MOSQ_ERR_PROTOCOL:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] There is a protocol "
                               "error communicating with the broker.");
                        pObj->m_bQuit = true;
                        break;

                    case MOSQ_ERR_ERRNO:
                        char buf[128];
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] A systemcall returned "
                               "an error [%d] %s",
                               errno,
                               strerror_r(errno, buf, sizeof(buf)));
                        pObj->m_bQuit = true;
                        break;
                }
            } // mosquito loop
        }     // while

        if (MOSQ_ERR_SUCCESS !=
            (rv = mosquitto_unsubscribe(mosq, NULL, pObj->m_topic.c_str()))) {
            switch (rv) {
                case MOSQ_ERR_INVAL:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] An input parameters are "
                           "invalid.");
                    break;

                case MOSQ_ERR_NOMEM:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] An out of memory condition "
                           "occurred..");
                    break;

                case MOSQ_ERR_NO_CONN:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] The client isn’t connected "
                           "to a broker.");
                    break;

                case MOSQ_ERR_MALFORMED_UTF8:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] The topic is not "
                           "valid UTF-8");
                    break;

                case MOSQ_ERR_OVERSIZE_PACKET:
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] The resulting packet would "
                           "be larger than supported by the broker.");
                    break;
            }
        }

    } else {

        // * * * publish * * *

        std::string str;

        while (!pObj->m_bQuit) {

            // Send heartbeat if it's time for that
            if ((vscp_getMsTimeStamp() - timestamp) > 60000) {

                timestamp = vscp_getMsTimeStamp();

                vscpEvent* pEvent = new vscpEvent;
                if (NULL == pEvent) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Unable to add "
                           "incoming event due to "
                           "memory problem (event).");
                    pObj->m_bQuit = true;
                    continue;
                }

                pEvent->head      = VSCP_HEADER16_DUMB;
                pEvent->obid      = 0;
                pEvent->timestamp = 0; // Let i&f set timestamp
                vscp_setEventToNow(pEvent);
                pEvent->vscp_class = VSCP_CLASS1_INFORMATION;
                pEvent->vscp_type  = VSCP_TYPE_INFORMATION_NODE_HEARTBEAT;
                pEvent->sizeData   = 3;
                pEvent->pdata      = new uint8_t[3];
                if (NULL == pEvent->pdata) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Out of memory problem when "
                           "sending heartbeat.");
                    pObj->m_bQuit = true;
                    continue;
                }
                pEvent->pdata[0] = pObj->m_index;
                pEvent->pdata[1] = pObj->m_zone;
                pEvent->pdata[2] = pObj->m_subzone;
                pObj->m_guid.writeGUID(pEvent->GUID);

                if (!pObj->addEvent2ReceiveQueue(pEvent)) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] Unable to add publish "
                           "heatbeat event.");
                    vscp_deleteEvent_v2(&pEvent);
                }
            }

            if (MOSQ_ERR_SUCCESS != (rv = mosquitto_loop(mosq, 10, 1))) {
                switch (rv) {
                    case MOSQ_ERR_INVAL:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] An input "
                               "parameters are "
                               "invalid.");
                        pObj->m_bQuit = true;
                        break;

                    case MOSQ_ERR_NOMEM:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] An out of memory "
                               "condition "
                               "occurred..");
                        pObj->m_bQuit = true;
                        break;

                    case MOSQ_ERR_NO_CONN:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] The client isn’t "
                               "connected "
                               "to a broker.");
                        pObj->m_bQuit = true;
                        break;

                    case MOSQ_ERR_CONN_LOST:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] The connection to the "
                               "broker was lost.");
                        break;

                    case MOSQ_ERR_PROTOCOL:
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] There is a protocol "
                               "error communicating with the broker.");
                        pObj->m_bQuit = true;
                        break;

                    case MOSQ_ERR_ERRNO:
                        char buf[128];
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] A systemcall returned "
                               "an error [%d] %s",
                               errno,
                               strerror_r(errno, buf, sizeof(buf)));
                        pObj->m_bQuit = true;
                        break;
                }
            }

            struct timespec ts;
            ts.tv_sec  = 0;
            ts.tv_nsec = 10000; // 10 ms
            if (ETIMEDOUT == sem_timedwait(&pObj->m_semSendQueue, &ts)) {
                continue;
            }

            if (pObj->m_sendList.size()) {

                pthread_mutex_lock(&pObj->m_mutexSendQueue);
                vscpEvent* pEvent = pObj->m_sendList.front();
                pObj->m_sendList.pop_front();
                pthread_mutex_unlock(&pObj->m_mutexSendQueue);

                if (pObj->m_bDebug) {
                    std::string strEvent = vscp_getEventAsString(pEvent);
                    syslog(LOG_DEBUG,
                           "Event received to publish [%s]",
                           strEvent.c_str());
                }

                if (NULL == pEvent) {
                    syslog(LOG_ERR,
                           "[vscpl2drv-mqtt] A null event "
                           "received. Skipping.");
                    continue;
                }

                // If simple there must also be data
                if (pObj->m_bSimplify && vscp_isMeasurement(pEvent)) {

                    // Must be data
                    if ((NULL == pEvent->pdata)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-mqtt] A malformed "
                               "measurement event "
                               "received (no data). Skipping.  ");
                        vscp_deleteEvent(pEvent);
                        continue;
                    }

                    // Get measurement value
                    vscp_getMeasurementAsString(str, pEvent);

                    switch (pObj->m_simple_vscpclass) {

                        case VSCP_CLASS2_MEASUREMENT_FLOAT:
                        case VSCP_CLASS2_MEASUREMENT_STR: {

                            // Control block must be there
                            if (pEvent->sizeData < 4) {
                                std::string strEvent =
                                  vscp_getEventAsString(pEvent);
                                syslog(LOG_ERR,
                                       "Measurement event has invalid format "
                                       "[%s]",
                                       strEvent.c_str());
                                vscp_deleteEvent_v2(&pEvent);
                                continue;
                            }

                            // Sensor index must be the same
                            if ((-1 != pObj->m_simple_sensorindex) &&
                                (pObj->m_simple_index != pEvent->pdata[0])) {
                                vscp_deleteEvent_v2(&pEvent);
                                continue;
                            }

                            // Zone must be the same
                            if ((-1 != pObj->m_simple_zone) &&
                                (pObj->m_simple_zone != pEvent->pdata[1])) {
                                vscp_deleteEvent_v2(&pEvent);
                                continue;
                            }

                            // Subzone must be the same
                            if ((-1 != pObj->m_simple_subzone) &&
                                (pObj->m_simple_zone != pEvent->pdata[2])) {
                                vscp_deleteEvent_v2(&pEvent);
                                continue;
                            }

                            // Unit must be the same
                            if ((-1 != pObj->m_simple_unit) &&
                                (pObj->m_simple_unit != pEvent->pdata[3])) {
                                vscp_deleteEvent_v2(&pEvent);
                                continue;
                            }

                            goto PUBLISH;
                        } break;

                        default:
                        case VSCP_CLASS1_MEASUREMENT: {

                            // Control block must be there
                            if (0 == pEvent->sizeData) {
                                vscp_deleteEvent_v2(&pEvent);
                                continue;
                            }

                            // Sensor index must be the same
                            if ((-1 != pObj->m_simple_sensorindex) &&
                                (pObj->m_simple_sensorindex !=
                                 VSCP_DATACODING_INDEX(pEvent->pdata[0]))) {
                                vscp_deleteEvent_v2(&pEvent);
                                continue;
                            }

                            // Unit must be the same
                            if ((-1 != pObj->m_simple_unit) &&
                                (pObj->m_simple_unit !=
                                 VSCP_DATACODING_UNIT(pEvent->pdata[0]))) {
                                vscp_deleteEvent_v2(&pEvent);
                                continue;
                            }

                            goto PUBLISH;

                        } break;

                    } // switch

                } else if (!pObj->m_bSimplify) { // Not measurement and simplify

                    switch (pObj->m_format) {

                        case VSCP_MQTT_FORMAT_STRING:
                            !vscp_convertEventToString(str, pEvent);
                            break;

                        case VSCP_MQTT_FORMAT_XML:
                            vscp_convertEventToXML(str, pEvent);
                            break;

                        case VSCP_MQTT_FORMAT_JSON:
                            vscp_convertEventToJSON(str, pEvent);
                            break;

                        default:
                            std::string strEvent =
                              vscp_getEventAsString(pEvent);
                            syslog(LOG_ERR,
                                   "Invalid format %d"
                                   "[%s]",
                                   pObj->m_format,
                                   strEvent.c_str());
                            vscp_deleteEvent_v2(&pEvent);
                            continue;
                    }

                PUBLISH:

                    // if topic is empty we should build a topic on the form
                    // prefix + "/vscp/guid/class/type"
                    cguid guid(pEvent->GUID);
                    std::string topic = pObj->m_prefix;
                    if (pObj->m_topic.length()) {
                        topic += pObj->m_topic;
                    } else {
                        topic = vscp_str_format("%s/vscp/%s/%d/%d",
                                                pObj->m_prefix.c_str(),
                                                guid.getAsString().c_str(),
                                                pEvent->vscp_class,
                                                pEvent->vscp_type);
                    }

                    if (pObj->m_bDebug) {
                        syslog(
                          LOG_DEBUG,
                          "[vscpl2drv-mqtt] publising to host %s topic %s [%s]",
                          pObj->m_host.c_str(),
                          pObj->m_topic.c_str(),
                          str.c_str());
                    }

                    if (MOSQ_ERR_SUCCESS !=
                        (rv = mosquitto_publish(mosq,
                                                NULL,
                                                topic.c_str(),
                                                str.length(),
                                                str.c_str(),
                                                pObj->m_qos,
                                                false))) {
                        switch (rv) {

                            case MOSQ_ERR_INVAL:
                                syslog(LOG_ERR,
                                       "[vscpl2drv-mqtt] Input "
                                       "parameters were "
                                       "invalid.");
                                pObj->m_bQuit = true;
                                break;

                            case MOSQ_ERR_NOMEM:
                                syslog(LOG_ERR,
                                       "[vscpl2drv-mqtt] An out of "
                                       "memory "
                                       "condition occurred.");
                                pObj->m_bQuit = true;
                                break;

                            case MOSQ_ERR_NO_CONN:
                                syslog(LOG_ERR,
                                       "[vscpl2drv-mqtt] The "
                                       "client isn’t "
                                       "connected to a broker.");
                                pObj->m_bQuit = true;
                                break;

                            case MOSQ_ERR_PROTOCOL:
                                syslog(LOG_ERR,
                                       "[vscpl2drv-mqtt] There is "
                                       "a protocol "
                                       "error communicating with "
                                       "the broker.");
                                pObj->m_bQuit = true;
                                break;

                            case MOSQ_ERR_PAYLOAD_SIZE:
                                syslog(LOG_ERR,
                                       "[vscpl2drv-mqtt] The "
                                       "payloadlen is too "
                                       "large.");
                                pObj->m_bQuit = true;
                                break;

                            case MOSQ_ERR_MALFORMED_UTF8:
                                syslog(LOG_ERR,
                                       "[vscpl2drv-mqtt] The topic "
                                       "is not "
                                       "valid UTF-8");
                                pObj->m_bQuit = true;
                                break;

                            case MOSQ_ERR_QOS_NOT_SUPPORTED:
                                syslog(LOG_ERR,
                                       "[vscpl2drv-mqtt] The QoS "
                                       "is greater "
                                       "than that supported by the "
                                       "broker.");
                                pObj->m_bQuit = true;
                                break;

                            case MOSQ_ERR_OVERSIZE_PACKET:
                                syslog(LOG_ERR,
                                       "[vscpl2drv-mqtt] The "
                                       "resulting packet would "
                                       "be larger than supported "
                                       "by the broker.");
                                pObj->m_bQuit = true;
                                break;
                        }
                    }
                }

                // We are done with the event
                vscp_deleteEvent_v2(&pEvent);

            } // Event received
        }     // while not bQuit
    }

    if (MOSQ_ERR_SUCCESS != (rv = mosquitto_disconnect(mosq))) {
        switch (rv) {

            case MOSQ_ERR_INVAL:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] Disconnect. Invalid input "
                       "parameter.");
                break;

            case MOSQ_ERR_NO_CONN:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] Disconnect. Not connected "
                       "to a broker.");
                break;
        }
    }

    if (MOSQ_ERR_SUCCESS != (rv = mosquitto_loop_stop(mosq, false))) {
        switch (rv) {

            case MOSQ_ERR_INVAL:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] Stop Loop. Invalid "
                       "input parameter.");
                break;

            case MOSQ_ERR_NOT_SUPPORTED:
                syslog(LOG_ERR,
                       "[vscpl2drv-mqtt] Stop loop. Tread "
                       "support not available.");
                break;
        }
    }

    mosquitto_destroy(mosq);
    return NULL;
}
