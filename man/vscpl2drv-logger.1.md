% vscpl2drv-mqtt(1) VSCP Level II Logger Driver
% Åke Hedman, Grodans Paradis AB
% September 28, 2019

# NAME

vscpl2drv-mqtt - VSCP Level I Logger Driver

# SYNOPSIS

vscpl2drv-mqtt

# DESCRIPTION

vscpd level II driver for diagnostic logging. It makes it possible to log VSCP events to a file. Two formats of the log file is supported. Either a standard log file with a standard text string for each event on each line or loggings can be written on XML format. The advantage ofthe later is that it can be read by VSCP works and further analyzed there. Several drivers can be loaded logging data to different output files and using different filter/masks.

## Configuration string

A VSCP level II driver have access to the tcp/ip interface of the machine is is installed on and frin that host get unique credentials to allow it to log in to the tcp/ip interface. The driver can use this as a method to initially fetch configuration parameters. The link is  also used to as pass other data such as events to/from the server.

The configuration string for vscpl2drv-mqtt (set in */etc/vscp/vscpd.conf*) have the following format

```bash
path;rewrite;vscpworksfmt;filter;mask
```

* **path** - The absolute or relative path including the file name to the file that log data should be written to. Mandatory.
* **rewrite** - Set to 'true' to create a new file or rewrite data over an old file with new data. Set to 'false' to append data to an existing file (create it if it's not available). Defaults to 'false'.
* **filter** - A Standard VSCP filter in string from 'priority,class,type,GUID'. Example: '1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00'. Defaults to an all zero filter.
* **mask** - Standard VSCP mask in string form 'priority,class,type,GUID'. Example: 1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00. Defaults to an all zero mask.

The configuration string is the first configuration data that is read. The driver will, after it is read, ask the server for driver specific configuration data. This data is fetched with the same pattern for all drivers. Variables are formed by the driver name + some driver specific variable name. If this variable exist and contains data this will be used as configuration for the driver.

For the vscpl2drv-mqtt the following configuration variables are defined

| Variable name | Type | Description |
| ------------- | :--: | ----------- |
| **_path** | string | Path to the logfile. |
| **_rewrite** | bool | Set to “true” to rewrite the file each time the driver is started. Set to “false” to append to file. |
| **_vscpworksfmt** | bool | If “true” VSCP works XML format will be used for the log file. This means that the file will be possible to read and further analyzed by VSCP Works. If “false” a standard text based format will be used. |
| **_filter** | string | Standard VSCP filter in string from. 1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00 as priority,class,type,GUID |
| **_mask** | string | Standard VSCP mask in string form. 1,0x0000,0x0006,ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00 as priority,class,type,GUID |

## Example of vscpd.conf entry for the logger driver.

```xml
<driver enable="true" >
    <name>log1</name>
    <path>/usr/local/lib/vscpl2_loggerdrv.so</path>
    <config>/tmp/vscp_level2.log</config>
    <guid>00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00</guid>
</driver>
```
I this case the driver will fetch configuration data from the server from variables *log1_path, log1_rewrite, log1_vscpworksfmt, log1_filter and  log1_mask*


---

There are many Level I drivers available in VSCP & Friends framework that can be used with both VSCP Works and the VSCP Daemon and added to that Level II and Level III drivers that can be used with the VSCP Daemon.

Level I drivers is documented [here](https://grodansparadis.gitbooks.io/the-vscp-daemon/level_i_drivers.html).

Level II drivers is documented [here](https://grodansparadis.gitbooks.io/the-vscp-daemon/level_ii_drivers.html)

Level III drivers is documented [here](https://grodansparadis.gitbooks.io/the-vscp-daemon/level_iii_drivers.html)

# SEE ALSO

`vscpd` (8).
`uvscpd` (8).
`vscpworks` (1).
`vscpcmd` (1).
`vscp-makepassword` (1).
`vscphelperlib` (1).

The VSCP project homepage is here <https://www.vscp.org>.

The [manual](https://grodansparadis.gitbooks.io/the-vscp-daemon) for vscpd contains full documentation. Other documentation can be found here <https://grodansparadis.gitbooks.io>.

The vscpd source code may be downloaded from <https://github.com/grodansparadis/vscp>. Source code for other system components of VSCP & Friends are here <https://github.com/grodansparadis>

# COPYRIGHT
Copyright 2000-2019 Åke Hedman, Grodans Paradis AB - MIT license.