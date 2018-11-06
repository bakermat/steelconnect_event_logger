#!/usr/local/bin/python3
""" Script to setup specific logging to file and text via Twilio

Requirements:
- Python 3.6+
- requests
- steelconnection
- twilio

To install these: "pip3 install requests twilio steelconnection"
TODO:
- look into args/kwargs for format_message ?
"""
import datetime
import time
import signal
import sys
import configparser
import logging
from logging.handlers import RotatingFileHandler
from collections import namedtuple
import re
import requests
import steelconnection
from twilio.rest import Client

# read and parse config from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')
try:
    SCM_REALM = config['SCM']['REALM']
    SCM_USER = config['SCM']['USERNAME']
    SCM_PW = config['SCM']['PASSWORD']
    SCM_RETRY_TIMER = int(config['SCM']['RETRY_TIMER'])
    TW_ACCOUNT_SID = config['TWILIO']['ACCOUNT_SID']
    TW_AUTH_TOKEN = config['TWILIO']['AUTH_TOKEN']
    TW_SENDER = config['TWILIO']['SENDER']
    TW_RECEIVER = config['TWILIO']['RECEIVER']
    LOGLEVEL_LOGFILE = config['LOGGING']['LEVEL_LOGFILE']
    LOGLEVEL_CONSOLE = config['LOGGING']['LEVEL_CONSOLE']
except KeyError:
    print("Error: Can't read config.ini file.")
    sys.exit(0)
except ValueError as e:
    print("Incorrect value detected: " + str(e))
    sys.exit(0)

# initialise global variables
TWILIO_CLIENT = Client(TW_ACCOUNT_SID, TW_AUTH_TOKEN)
messages_log = []
messages_sms = []
offline_timestamp = {}
first_run = True
scm_logger = logging.getLogger()
# save values from config file in MESSAGES_xxx in lowercase for comparison
for option, value in config.items('MESSAGES_LOG'):
    messages_log.append(value.lower())
for option, value in config.items('MESSAGES_SMS'):
    messages_sms.append(value.lower())

# Setup connection to SCM
try:
    sc = steelconnection.SConnect(SCM_REALM, SCM_USER, SCM_PW)
except Exception as error:
    print(str(error))


def handle_error(function):
    """ Function to capture possible errors """
    def handle_problems(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except requests.exceptions.RequestException:
            scm_logger.error("Error: can't connect to %s. Retrying in %s seconds.", SCM_REALM, SCM_RETRY_TIMER)
            time.sleep(SCM_RETRY_TIMER)
            main()
        except steelconnection.exceptions.AuthenticationError:
            scm_logger.error("401 Error: Incorrect username or password for %s.", SCM_REALM)
            sys.exit(0)
        except steelconnection.exceptions.APINotEnabled:
            scm_logger.error("502 Error: REST API is not enabled on %s.", SCM_REALM)
            sys.exit(0)
    return handle_problems


def log_setup():
    """Setup logging levels for imported modules, rotating logfile and console """
    logging.getLogger('twilio.http_client').setLevel(logging.WARNING)
    logging.getLogger('steelconnection.api').setLevel(logging.ERROR)

    formatter = logging.Formatter("%(asctime)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    scm_logger.setLevel(LOGLEVEL_LOGFILE.upper())
    # create rotating file handler and get loglevel from config file
    file_handler = RotatingFileHandler("output.log", maxBytes=1024 * 1000 * 10, backupCount=5)
    file_handler.setFormatter(formatter)
    scm_logger.addHandler(file_handler)
    # create console handler and get loglevel from config file
    console = logging.StreamHandler()
    console.setLevel(LOGLEVEL_CONSOLE.upper())
    # for console we only want message as we get timestamp from SCM event log
    formatter = logging.Formatter("%(message)s")
    console.setFormatter(formatter)
    scm_logger.addHandler(console)


@handle_error
def get_items(sc, items):
    """ Get all items. """
    items = sc.get(items)
    return items


@handle_error
def get_events(sc):
    """ Get all event_logs and reverse order to make ascending. """
    events = sc.getstatus('event_logs')
    events.reverse()
    return events


def get_node_details(sc, sites, nodes):
    """Get node and site details, put in Node object"""
    node_details = []
    for site in sites:
        for node in nodes:
            if node['site'] == site['id']:
                site_name = site['name']
                site_id = site['id']
                model = sc.lookup.model(node['model'])
                serial = node['serial'] or 'shadow'
                node_id = node['id']
                Node = namedtuple('Node', ['site_name', 'site_id', 'node_id',
                                           'model', 'serial'])
                node_details.extend([Node(site_name, site_id, node_id, model, serial)])
    return node_details


def print_to_log(msg, event):
    """Send info level message and debug event details to logger"""
    scm_logger.debug("%s: ", str(event))
    scm_logger.info(msg)


def get_event_details(events, sites):
    """Get all event details, put in Event object"""
    event_details = []
    for event in events:
        site_name = None
        node = event['node']
        org = event['org']
        timestamp = event['utc']
        msg = event['msg']
        site_id = event['site']
        severity = event['severity']
        time_formatted = str(datetime.datetime.fromtimestamp(timestamp, tz=None))
        event_id = event['id']
        for site in sites:
            if event['site'] == site['id']:
                site_name = site['name']
        Event = namedtuple('Event', ['timestamp', 'time_formatted', 'node', 'org', 'msg', 'site_id',
                                     'site_name', 'severity', 'event_id'])
        event_details.extend([Event(timestamp, time_formatted, node, org, msg, site_id,
                                    site_name, severity, event_id)])
    return event_details


def find_and_replace_object_ids(msg, sc):
    """Find IDs in string and use get_event_object() to make it human-readable, use
    get_event_object to replace the ID with text. Do this for each resource_type as event msg can
    have multiple IDs in one message.
    """
    # using a dict as segment/zone call is different to the other ones
    resource_types = {'uplink': 'uplink', 'port': 'port', 'site': 'site',
                      'wan': 'wan', 'segment': 'zone'}
    for search_string, api_call in resource_types.items():
        if 'Deleted' not in msg:
            resource_id = re.findall(r'(?<=id )%s[^. ]*' % search_string, msg, flags=re.IGNORECASE)
            msg = get_event_object(resource_id, api_call, sc, msg)
    return msg


def get_event_object(object_id, api_call, sc, message):
    """Replace IDs with human-readable names"""
    # len(object_id) is > 0 when object (uplink/site/wan) is found
    if len(object_id) >= 1:
        for index, item in enumerate(object_id):
            try:
                # workaround for SDI-5030: uses 'dcuplink' instead of 'uplink'
                if 'dcuplink' in object_id[index]:
                    resource = sc.get('dcuplink/' + object_id[index])
                else:
                    resource = sc.get(api_call + '/' + object_id[index])
                    name = resource['tag'] if api_call == 'port' else resource['name']
                message = message.replace("ID "+item, name)
            except steelconnection.exceptions.InvalidResource:
                # happens when there's an event in a org you don't have permissions for. Ignore.
                pass
    return message


def send_twilio_message(receiver, sender, body):
    """Send message to phone number using Twilio API. Try to connect 3 times."""
    for _ in range(3):
        try:
            TWILIO_CLIENT.messages.create(
                to=receiver,
                from_=sender,
                body=body
                )
        except requests.exceptions.RequestException:
            scm_logger.error("Error communicating with Twilio API. Retrying.")
        else:
            scm_logger.debug("SMS sent successfully: %s", body)
            break
    else:
        scm_logger.info("Couldn't connect to Twilio to send message.")


def format_message(date_str, node, msg):
    """Format log message"""
    message = f"{date_str}: {node.site_name}: {node.model} ({node.serial}) {msg}"
    return message


# def get_message(node_detail, msg, timestamp, time_formatted, log=False):
def get_offline_duration(node_detail, msg, timestamp, log=False):
    """Format event message, and calculate appliance offline duration"""
    if msg == 'Appliance went offline':
        offline_timestamp[node_detail.node_id] = timestamp
    elif msg == 'Appliance came online':
        if node_detail.node_id in offline_timestamp:
            offline_total_time = timestamp - offline_timestamp[node_detail.node_id]
            duration = datetime.timedelta(seconds=offline_total_time)
            if log:
                del offline_timestamp[node_detail.node_id]
            msg = msg + f". Offline for {duration}."
    return msg


def check_if_in_messages(sc, messages_list, event_detail, node_details, log=True):
    """Send to log/text when event_detail.msg is in the messages_XXX list"""
    if any(s in event_detail.msg.lower() for s in messages_list):
        msg = find_and_replace_object_ids(event_detail.msg, sc)
        for node_detail in node_details:
            if node_detail.node_id == event_detail.node:
                message = get_offline_duration(node_detail, msg, event_detail.timestamp, log)
                message = format_message(event_detail.time_formatted, node_detail, message)
                if log:
                    print_to_log(message, event_detail)
                else:
                    send_twilio_message(TW_RECEIVER, TW_SENDER, message)
                break
            elif event_detail.node is None:
                site_name = 'N/A' if event_detail.site_name is None else event_detail.site_name
                # this happens when no node details are available
                message = f"{event_detail.time_formatted}: {site_name}: {msg}"
                print_to_log(message, event_detail)
                break


@handle_error
def main():
    """Main function"""
    global first_run
    if first_run:
        log_setup()
        scm_logger.debug("====== Starting application ======")
        scm_logger.info("Connecting to %s", SCM_REALM)

    # last_check_event_id is used to compare against most recent event id
    last_check_event_id = -1

    while True:
        nodes = get_items(sc, 'nodes')
        sites = get_items(sc, 'sites')
        if first_run:
            scm_logger.info("Successfully connected to %s", SCM_REALM)
            first_run = False
        # for each site, go through nodes and save details in Node object
        node_details = get_node_details(sc, sites, nodes)
        events = get_events(sc)
        most_recent_event_id = events[-1]['id']
        event_details = get_event_details(events, sites)
        for event_detail in event_details:
            if (event_detail.event_id > last_check_event_id) and (last_check_event_id is not -1):
                check_if_in_messages(sc, messages_sms, event_detail, node_details, False)
                check_if_in_messages(sc, messages_log, event_detail, node_details, True)
        last_check_event_id = most_recent_event_id
        # wait X seconds, then do it again
        time.sleep(SCM_RETRY_TIMER)


def signal_handler(sig, frame):
    """Catch CTRL+C when exiting application for clean exit. """
    scm_logger.info("\nCTRL+C pressed. Bye!")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
if __name__ == "__main__":
    main()
