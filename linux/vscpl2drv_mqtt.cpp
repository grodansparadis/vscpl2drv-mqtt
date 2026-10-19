// vscp2drv_mqtt.cpp : Defines the initialization routines for the DLL.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2020 Ake Hedman,
// Grodans Paradis AB, <akhe@grodansparadis.com>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#ifdef __GNUG__
//#pragma implementation
#endif

#include <map>
#include <string>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <cerrno>

#include <canal.h>
#include <canal-macro.h>
#include <vscp.h>
#include <vscphelper.h>

#include "../common/mqttobj.h"
#include "vscpl2drv_mqtt.h"

// This map holds driver handles/objects
static std::map<long, Cmqttobj*> g_ifMap;

// Mutex for the map object
static pthread_mutex_t g_mapMutex = PTHREAD_MUTEX_INITIALIZER;

class DriverObjectCleanup
{
  public:
    ~DriverObjectCleanup()
    {
        pthread_mutex_lock(&g_mapMutex);
        for (std::map<long, Cmqttobj*>::iterator it = g_ifMap.begin();
             it != g_ifMap.end();
             ++it) {
            delete it->second;
        }
        g_ifMap.clear();
        pthread_mutex_unlock(&g_mapMutex);
    }
};

static DriverObjectCleanup g_driverObjectCleanup;

///////////////////////////////////////////////////////////////////////////////
// addDriverObject
//

long
addDriverObject(Cmqttobj* pif)
{
    std::map<long, Cmqttobj*>::iterator it;
    long h = 0;

    pthread_mutex_lock(&g_mapMutex);

    // Find free handle
    while (true) {
        if (g_ifMap.end() == (it = g_ifMap.find(h)))
            break;
        h++;
    };

    g_ifMap[h] = pif;
    h += 1681;

    pthread_mutex_unlock(&g_mapMutex);

    return h;
}

///////////////////////////////////////////////////////////////////////////////
// getDriverObject
//

Cmqttobj*
getDriverObject(long h)
{
    std::map<long, Cmqttobj*>::iterator it;
    long idx = h - 1681;

    // Check if valid handle
    if (idx < 0)
        return NULL;

    it = g_ifMap.find(idx);
    if (it != g_ifMap.end()) {
        return it->second;
    }

    return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// removeDriverObject
//

void
removeDriverObject(long h)
{
    std::map<long, Cmqttobj*>::iterator it;
    long idx = h - 1681;

    // Check if valid handle
    if (idx < 0)
        return;

    pthread_mutex_lock(&g_mapMutex);
    it = g_ifMap.find(idx);
    if (it != g_ifMap.end()) {
        Cmqttobj* pObj = it->second;
        if (NULL != pObj) {
            delete pObj;
            pObj = NULL;
        }
        g_ifMap.erase(it);
    }
    pthread_mutex_unlock(&g_mapMutex);
}

///////////////////////////////////////////////////////////////////////////////
//                         V S C P   D R I V E R -  A P I
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// VSCPOpen
//

extern "C" long
VSCPOpen(const char* pPathConfig, const char* pguid)
{
    long h = 0;

    Cmqttobj* pdrvObj = new Cmqttobj();
    if (NULL != pdrvObj) {

        std::string cfg(pPathConfig);
        cguid guid(pguid);

        if (pdrvObj->open(cfg, guid)) {

            if (!(h = addDriverObject(pdrvObj))) {
                delete pdrvObj;
            }

        } else {
            delete pdrvObj;
        }
    }

    return h;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPClose
//

extern "C" int
VSCPClose(long handle)
{
    Cmqttobj* pdrvObj = getDriverObject(handle);
    if (NULL == pdrvObj)
        return 0;
    pdrvObj->close();
    removeDriverObject(handle);
    return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPWrite
//

extern "C" int
VSCPWrite(long handle, const vscpEvent* pEvent, unsigned long timeout)
{
    Cmqttobj* pdrvObj = getDriverObject(handle);
    if (NULL == pdrvObj)
        return CANAL_ERROR_MEMORY;
    pdrvObj->addEvent2SendQueue(pEvent);

    return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
//  VSCPRead
//

extern "C" int
VSCPRead(long handle, vscpEvent* pEvent, unsigned long timeout)
{
    // Check pointer
    if (NULL == pEvent)
        return CANAL_ERROR_PARAMETER;

    Cmqttobj* pdrvObj = getDriverObject(handle);
    if (NULL == pdrvObj)
        return CANAL_ERROR_MEMORY;

    int rv;
    rv = pdrvObj->m_semReceiveQueue.waitFor(timeout);
    if (-1 == rv) {
        if (ETIMEDOUT == errno) {
            return CANAL_ERROR_TIMEOUT;
        } else if (EINTR == errno) {
            syslog(LOG_ERR,
                   "[vscpl2drv-mqtt] Interrupted by a signal handler");
            return CANAL_ERROR_INTERNAL;
        } else if (EINVAL == errno) {
            syslog(LOG_ERR,
                   "[vscpl2drv-mqtt] Invalid semaphore (timout)");
            return CANAL_ERROR_INTERNAL;
        } else if (EAGAIN == errno) {
            syslog(LOG_ERR, "[vscpl2drv-mqtt] Blocking error");
            return CANAL_ERROR_INTERNAL;
        } else {
            syslog(LOG_ERR, "[vscpl2drv-mqtt] Unknown error");
            return CANAL_ERROR_INTERNAL;
        }
    }

    pthread_mutex_lock(&pdrvObj->m_mutexReceiveQueue);
    vscpEvent* pLocalEvent = pdrvObj->m_receiveList.front();
    pdrvObj->m_receiveList.pop_front();
    pthread_mutex_unlock(&pdrvObj->m_mutexReceiveQueue);
    if (NULL == pLocalEvent)
        return CANAL_ERROR_MEMORY;

    vscp_copyEvent(pEvent, pLocalEvent);
    vscp_deleteEvent(pLocalEvent);

    return CANAL_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// VSCPGetVersion
//

extern "C" unsigned long
VSCPGetVersion(void)
{
    unsigned long ver = MAJOR_VERSION << 24 | MINOR_VERSION << 16 |
                        RELEASE_VERSION << 8 | BUILD_VERSION;
    return ver;
}
