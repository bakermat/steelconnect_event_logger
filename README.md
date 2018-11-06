# steelconnect_event_logger
Monitor specific SCM events based on user preferences. Output sent to screen or Twilio and log file.

## Getting Started
USAGE:
1) Update config.ini with your SCM and (optionally) Twilio account settings.
2) Execute steelconnect_event_logger.py

SteelConnect Manager is polled every 30 seconds.

### Prerequisites
- Python 3.6+
- requests
- steelconnection
- twilio

To install these: "pip3 install requests twilio steelconnection"