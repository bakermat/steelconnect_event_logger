# steelconnect_event_logger
Monitor specific SCM events based on user preferences. Output sent to screen or Twilio or ServiceNow and log file.

## Getting Started
USAGE:
1) Update config.ini with your SCM and (optionally) Twilio & ServiceNow account settings.
2) Execute steelconnect_event_logger.py

SteelConnect Manager is polled every 30 seconds.

### Prerequisites
- Python 3.6+
- requests
- steelconnection
- twilio

To install these: "pip3 install requests twilio steelconnection"

### Release Notes
v1.1: 2019-04-10
- Add support for ServiceNow incident creation
- Made Twilio + ServiceNow integration optional
- Minor bugfixes and code clean-up

v1.0: 2018-11-07
- Initial release

### Example of screen output using default settings
```
$ ./steelconnect_event_logger.py
Connecting to xxx.riverbed.cc
Successfully connected to xxx.riverbed.cc
2018-11-06 16:57:30: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Appliance has downloaded firmware version 2.10.2-23.
2018-11-06 17:00:09: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Port AUX edited: capab_uplink changed from Off to On.
2018-11-06 17:00:12: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Appliance firmware version is now 2.10.2-23.
2018-11-06 17:04:45: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Port AUX link state went DOWN
2018-11-06 17:04:45: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Port PRIMARY link state went DOWN
2018-11-06 17:04:45: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Port LAN0_0 link state went DOWN
2018-11-06 17:04:45: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Port WAN0_0 link state went UP
2018-11-06 17:04:45: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Port LAN0_1 link state went DOWN
2018-11-06 17:04:45: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Port WAN0_1 link state went DOWN
2018-11-06 17:05:26: SYDNEY-LAB: 570-SD (XN00000000C0FF33) External IPv4 address change on Uplink Uplink_MPLS (new IP )
2018-11-06 17:05:26: SYDNEY-LAB: 570-SD (XN00000000C0FF33) External IPv4 address change on Uplink Uplink_Internet (new IP )
2018-11-06 17:05:26: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Uplink Uplink_Internet is now in use
2018-11-06 17:05:26: SYDNEY-LAB: 570-SD (XN00000000C0FF33) Uplink Uplink_Internet came online
2018-11-06 17:07:11: SYDNEY-LAB: 570-SD (XN00000000C0FF33) External IPv4 address change on Uplink Uplink_Internet (new IP 172.31.21.4)
```