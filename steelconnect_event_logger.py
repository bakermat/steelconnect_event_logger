#!/usr/local/bin/python3
""" Script to setup specific logging to file, Twilio or ServiceNow (v1.1)

Requirements:
- Python 3.6+
- requests
- steelconnection
- twilio

Installation: "pip3 install requests twilio steelconnection"

"""

import datetime
import time
import signal
import sys
import configparser
import logging
import json
from logging.handlers import RotatingFileHandler
from collections import namedtuple
import re
import requests
import steelconnection
from twilio.rest import Client

scm_logger = logging.getLogger()

# read and parse config from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')
try:
    SCM_REALM = config['SCM']['REALM']
    SCM_USER = config['SCM']['USERNAME']
    SCM_PW = config['SCM']['PASSWORD']
    SCM_RETRY_TIMER = int(config['SCM']['RETRY_TIMER'])
    ENABLE_TWILIO = int(config['SERVICES']['ENABLE_TWILIO'])
    ENABLE_SERVICENOW = int(config['SERVICES']['ENABLE_SERVICENOW'])
    TW_ACCOUNT_SID = config['TWILIO']['ACCOUNT_SID']
    TW_AUTH_TOKEN = config['TWILIO']['AUTH_TOKEN']
    TW_SENDER = config['TWILIO']['SENDER']
    TW_RECEIVER = config['TWILIO']['RECEIVER']
    SN_URL = config['SERVICENOW']['URL']
    SN_USERNAME = config['SERVICENOW']['USERNAME']
    SN_PASSWORD = config['SERVICENOW']['PASSWORD']
    SN_CATEGORY = config['SERVICENOW']['CATEGORY']
    SN_SUBCATEGORY = config['SERVICENOW']['SUBCATEGORY']
    SN_CALLER_ID = config['SERVICENOW']['CALLER_ID']
    SN_CONTACT_TYPE = config['SERVICENOW']['CONTACT_TYPE']
    LOGLEVEL_LOGFILE = config['LOGGING']['LEVEL_LOGFILE']
    LOGLEVEL_CONSOLE = config['LOGGING']['LEVEL_CONSOLE']
except KeyError:
    scm_logger.error("Error: Can't read config.ini file.")
    sys.exit(0)
except ValueError as e:
    scm_logger.error(f"Incorrect value detected: {e}")
    sys.exit(0)

# initialise global variables
TWILIO_CLIENT = Client(TW_ACCOUNT_SID, TW_AUTH_TOKEN)
messages_log = []
messages_services = []
offline_timestamp = {}
first_run = True
# save values from config file in MESSAGES_xxx in lowercase for comparison
for option, value in config.items('MESSAGES_LOG'):
    messages_log.append(value.lower())
for option, value in config.items('MESSAGES_SERVICES'):
    messages_services.append(value.lower())

# Setup connection to SCM
try:
    sc = steelconnection.SConnect(SCM_REALM, SCM_USER, SCM_PW)
except Exception as error:
    scm_logger.error(error)


def handle_error(function):
    """ Function to capture possible errors """
    def handle_problems(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except requests.exceptions.RequestException:
            scm_logger.error(f"Error: can't connect to {SCM_REALM}. Retrying in {SCM_RETRY_TIMER} seconds.")
            time.sleep(SCM_RETRY_TIMER)
            main()
        except steelconnection.exceptions.AuthenticationError:
            scm_logger.error(f"401 Error: Incorrect username or password for {SCM_REALM}")
            sys.exit(0)
        except steelconnection.exceptions.APINotEnabled:
            scm_logger.error(f"502 Error: REST API is not enabled on {SCM_REALM}.")
            sys.exit(0)
        except Exception as e:
            scm_logger.error(e)
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
    formatter = logging.Formatter("%(asctime)s: %(message)s", "%Y-%m-%d %H:%M:%S")
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
                location = node['location']
                Node = namedtuple('Node', ['site_name', 'site_id', 'node_id',
                                           'location', 'model', 'serial'])
                node_details.extend([Node(site_name, site_id, node_id, location, model, serial)])
    return node_details


def print_to_log(msg, event):
    """Send info level message and debug event details to logger"""
    scm_logger.debug(f"{event}: ")
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
    resource_types = {'uplink': 'uplink', 'dcuplink': 'dcuplink', 'port': 'port', 'site': 'site',
                      'wan': 'wan', 'segment': 'zone', 'proxyservice': 'proxyservices'}
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
                resource = sc.get(api_call + '/' + object_id[index])
                if api_call == 'port':
                    name = resource['tag']
                elif api_call == 'proxyservices':
                    name = resource['city']
                else:
                    name = resource['name']
                message = message.replace("ID " + item, name)
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
                body=body)
        except requests.exceptions.RequestException:
            scm_logger.error("Error communicating with Twilio API. Retrying.")
        else:
            scm_logger.debug(f"SMS sent successfully: {body}.")
            break
    else:
        scm_logger.info("Couldn't connect to Twilio to send message.")


def send_servicenow_message(node_detail, event_detail, body):
    """Open ServiceNow incident"""
    auth = SN_USERNAME, SN_PASSWORD
    uri = f'{SN_URL}api/now/table/incident'

    # define http headers for request
    headers = {
        "Accept": "application/json;charset=utf-8",
        "Content-Type": "application/json"
    }

    # event_detail.severity = 0 for low prio events, so mapping that to ServiceNow severity 3
    severity = 3 if event_detail.severity is 0 else event_detail.severity
    if event_detail.severity is 0:
        severity = 3
    else:
        severity = event_detail.severity

    # define payload for request, note we are passing the sysparm_action variable in the body of the request
    payload = {
        'sysparm_action': 'insert',
        'short_description': f'{event_detail.site_name}: {node_detail.location or node_detail.model} ({node_detail.serial}) {body}',
        # following ones are optional
        'category': SN_CATEGORY,
        'subcategory': SN_SUBCATEGORY,
        'contact_type': SN_CONTACT_TYPE,
        'impact': severity,
        'urgency': severity,
        'description': f'{event_detail.time_formatted} {event_detail.site_name}: {node_detail.location or node_detail.model} ({node_detail.serial}) {body}',
        'cmdb_ci': node_detail.serial,
        'caller_id': SN_CALLER_ID,
    }
    try:
        r = requests.post(url=uri, data=json.dumps(payload), auth=auth, headers=headers)
        content = r.json()
    except requests.exceptions.RequestException:
        scm_logger.info(f'Code {str(r.status_code)}: Error {str(content)}')
    else:
        incident_uri = f'{SN_URL}nav_to.do?uri=incident.do?sys_id={content["result"]["sys_id"]}'
        scm_logger.info(f'ServiceNow: Incident {content["result"]["number"]} created. URL: {incident_uri}')


def format_message(date_str, node, msg):
    """Format log message"""
    message = f"{date_str}: {node.site_name}: {node.location or node.model} ({node.serial}) {msg}"
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
            msg = f'{msg}. Offline for {duration}.'
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
                    if ENABLE_TWILIO:
                        send_twilio_message(TW_RECEIVER, TW_SENDER, message)
                    if ENABLE_SERVICENOW:
                        send_servicenow_message(node_detail, event_detail, msg)
                break
            # this happens when no node details are available
            elif event_detail.node is None:
                site_name = '' if event_detail.site_name is None else f' {event_detail.site_name}:'
                message = f'{event_detail.time_formatted}:{site_name} {msg}'
                print_to_log(message, event_detail)
                break


@handle_error
def main():
    """Main function"""
    global first_run
    if first_run:
        log_setup()
        scm_logger.debug("====== Starting application ======")
        scm_logger.info(f"Connecting to {SCM_REALM}")

    # last_check_event_id is used to compare against most recent event id
    last_check_event_id = -1

    while True:
        nodes = get_items(sc, 'nodes')
        sites = get_items(sc, 'sites')
        if first_run:
            scm_logger.info(f"Successfully connected to {SCM_REALM}")
            first_run = False
        # for each site, go through nodes and save details in Node object
        node_details = get_node_details(sc, sites, nodes)
        events = get_events(sc)
        most_recent_event_id = events[-1]['id']
        event_details = get_event_details(events, sites)
        for event_detail in event_details:
            if (event_detail.event_id > last_check_event_id) and (last_check_event_id is not -1):
                check_if_in_messages(sc, messages_services, event_detail, node_details, False)
                check_if_in_messages(sc, messages_log, event_detail, node_details, True)
        last_check_event_id = most_recent_event_id
        # wait X seconds, then do it again
        time.sleep(SCM_RETRY_TIMER)


def signal_handler(sig, frame):
    """Catch CTRL+C when exiting application for clean exit. """
    scm_logger.info("CTRL+C pressed. Bye!")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
if __name__ == "__main__":
    main()
