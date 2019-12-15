// mqttobj.h: interface for the mqtt class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
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

#if !defined(_VSCPMQTT_H__INCLUDED_)
#define _VSCPMQTT_H__INCLUDED_

#include <list>
#include <string>

#include <stdio.h>
#include <string.h>
#include <time.h>

#define _POSIX
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>

#include <canal.h>
#include <canal_macro.h>
#include <guid.h>
#include <hlo.h>
#include <vscp.h>
#include <vscpremotetcpif.h>

// Forward declarations
class CWrkThread;
class Cmqtt;
class CWrkThreadObj;

// Connection types
#define VSCP_MQTT_TYPE_UNKNOWN 0
#define VSCP_MQTT_TYPE_SUBSCRIBE 1
#define VSCP_MQTT_TYPE_PUBLISH 2

#define VSCP_MQTT_FORMAT_STRING 0
#define VSCP_MQTT_FORMAT_XML 1
#define VSCP_MQTT_FORMAT_JSON 2
#define VSCP_MQTT_FORMAT_ENCRYPTED 3

#define ERROR_CODE_SUCCESS_PUBLISH 0
#define ERROR_CODE_SUCCESS_SUBSCRIBE 1
#define ERROR_CODE_SUCCESS_UNSUBSCRIBE 2

class Cmqttobj
{
  public:
    /// Constructor
    Cmqttobj();

    /// Destructor
    virtual ~Cmqttobj();

    /*!
        Open
        @return True on success.
     */
    bool open(std::string& pathcfg, cguid& guid);

    /*!
        Flush and close the log file
     */
    void close(void);

    /*!
        Add event to send queue

        @param pEvent Pointer to event that should be added
        @result True on success, false on failure
    */
    bool addEvent2SendQueue(const vscpEvent* pEvent);

    /*!
        Add event to receive queue

        @param pEvent Pointer to event that should be added
        @result True on success, false on failure
    */
    bool addEvent2ReceiveQueue(const vscpEvent* pEvent);

    /*!
        Load configuration

        @return true on success, false on failure
    */
    bool doLoadConfig(void);

    /*!
        Save configuration

        @return true on success, false on failure
    */
    bool doSaveConfig(void);

    /*!
        Parse HLO

        @param size Size of HLO object 0-511 bytes
        @param buf Pointer to buf containing HLO
        @param phlo Pointer to HLO that will get parsed data
        @return true on successfull parsing, false otherwise
    */
    bool parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo);

    /*!
        Handle HLO commands sent to this driver

        @param pEvent HLO event
        @return true on success, false on failure
    */
    bool handleHLO(vscpEvent* pEvent);

    /*!
        Put event on receive queue and signal
        that a new event is available

        @param ex Event to send
        @return true on success, false on failure
    */
    bool eventExToReceiveQueue(vscpEventEx& ex);

  public:
    /// Run flag
    bool m_bQuit;

    /// True enables debug output to syslog
    bool m_bDebug;

    /// True if config can be read onm command
    bool m_bRead;

    /// True if config can be written on comand
    bool m_bWrite;

    // Config file path
    std::string m_path;

    /// Unique GUID for this driver
    cguid m_guid;

    /// Event index for simple channel handling
    uint8_t m_index;

    /// zone for simple channel handling
    uint8_t m_zone;

    /// Subzone for simple channel handling
    uint8_t m_subzone;

    /// Connected flag
    bool m_bConnected;

    /// mqtt publish format
    uint8_t m_format;

    /// Session id
    std::string m_sessionid;

    /// server supplied prefix
    std::string m_prefix;

    /// Subscribe or Publish topic.
    std::string m_topic;

    /// Connection type (subscrive/publish/unknown)
    uint8_t m_type;

    // MQTT host (broker)
    std::string m_host;

    // MQTT port  tcp=1883, TSL over tcp = 8883
    int m_port;

    // MQTT username (broker)
    std::string m_username;

    // MQTT password (broker)
    std::string m_password;

    // Keepalive value
    int m_keepalive;

    // Quality Of Service
    uint8_t m_qos;

    /*!
        Event simplification
    */
    std::string m_simplify;

    /// Flag for simple channel handling
    bool m_bSimplify;

    /// Class for simple channel handling
    uint16_t m_simple_vscpclass;

    /// Type for simple channel handling
    int m_simple_vscptype;

    /// Coding for simple channel handling
    int m_simple_coding;

    /// Unit for simple channel handling
    int m_simple_unit;

    /// Sensor index for simple channel handling
    int m_simple_sensorindex;

    /// Event index for simple channel handling
    int m_simple_index;

    /// zone for simple channel handling
    int m_simple_zone;

    /// Subzone for simple channel handling
    int m_simple_subzone;

    /// path to a file containing the PEM encoded trusted CA certificate files.
    /// Either cafile or capath must not be NULL.
    std::string m_cafile;

    /// path to a directory containing the PEM encoded trusted CA certificate
    /// files.  See mosquitto.conf for more details on configuring this
    /// directory.  Either cafile or capath must not be NULL.
    std::string m_capath;

    /// path to a file containing the PEM encoded certificate file for this
    /// client.  If NULL, keyfile must also be NULL and no client certificate
    /// will be used.
    std::string m_certfile;

    /// path to a file containing the PEM encoded private key for this client.
    /// If NULL, certfile must also be NULL and no client certificate will be
    /// used.
    std::string m_keyfile;

    /// Enable encryption
    bool bEnableEncryption;

    /// Receive Filter
    vscpEventFilter m_vscpfilterRx;

    /// Transmit Filter
    vscpEventFilter m_vscpfilterTx;

    /// Pointer to worker thread
    pthread_t m_threadWork;

    // Queue
    std::list<vscpEvent*> m_sendList;
    std::list<vscpEvent*> m_receiveList;

    /*!
        Event object to indicate that there is an event in the output queue
    */
    sem_t m_semSendQueue;
    sem_t m_semReceiveQueue;

    // Mutex to protect the output queue
    pthread_mutex_t m_mutexSendQueue;
    pthread_mutex_t m_mutexReceiveQueue;
};

#endif // defined _VSCPMQTT_H__INCLUDED_
