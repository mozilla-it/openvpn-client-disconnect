"""
    Script to report on disconnecting VPN clients
"""
import os
import sys
import ast
import time
import datetime
import socket
import json
import syslog
from argparse import ArgumentParser
import configparser
import pytz
sys.dont_write_bytecode = True


ALWAYS_SHARE_METRICS = set(['common_name', 'time_unix'])
NEVER_SHARE_METRICS = set(['config', 'daemon', 'daemon_log_redirect',
                           'daemon_pid', 'daemon_start_time', 'verb',
                           'script_context', 'auth_control_file',
                           'password'])

def log_metrics_to_disk(usercn, metrics_log_dir, metrics_requested):
    """
        Using the set of metrics that we are requested to log, log
        the wad of variables to discrete files in a spool directory.
    """
    existing_requested_metrics = set(os.environ.keys()) & set(metrics_requested)
    safe_requested_metrics = existing_requested_metrics - NEVER_SHARE_METRICS
    metrics_to_log = safe_requested_metrics | ALWAYS_SHARE_METRICS

    directory_log = {x:os.environ.get(x, '') for x in metrics_to_log}

    if metrics_log_dir:
        epoch_seconds = int(directory_log.get('time_unix'))
        date = time.strftime('%Y%m%d%H%M%S', time.gmtime(epoch_seconds))
        filename = 'log.{usercn}.{date}.json'.format(usercn=usercn,
                                                     date=date)
        # Future tweak: ability to change the filename structure?
        outfile = '{path}/{filename}'.format(path=metrics_log_dir,
                                             filename=filename)
        buf = '{}\n'.format(json.dumps(directory_log,
                                       sort_keys=True,
                                       indent=2))
        with open(outfile, 'w') as outhandle:
            outhandle.write(buf)

def log_event(usercn, log_facility):
    '''
        Use the syslog module to log disconnection events.
    '''
    quick_metrics = {'username': usercn,
                     'bytesreceived': os.environ.get('bytes_received', ''),
                     'bytessent': os.environ.get('bytes_sent', ''),
                     'vpnip': os.environ.get('ifconfig_pool_remote_ip', ''),
                     'sourceport': os.environ.get('trusted_port', ''),
                     'connectionduration': os.environ.get('time_duration', ''),
                     'sourceipaddress': os.environ.get('trusted_ip', ''),
                     'success': 'true'}

    output_json = {
        'category': 'authentication',
        'processid': os.getpid(),
        'severity': 'INFO',
        'processname': sys.argv[0],
        # Have to use pytz because py2 is terrible here.
        'timestamp': pytz.timezone('UTC').localize(datetime.datetime.utcnow()).isoformat(),
        'details': quick_metrics,
        'hostname': socket.getfqdn(),
        'summary': 'SUCCESS: VPN disconnection for {}'.format(usercn),
        'tags': ['vpn', 'disconnect'],
        'source': 'openvpn',
    }
    syslog_message = json.dumps(output_json)
    syslog.openlog(facility=log_facility)
    syslog.syslog(syslog_message)

def _ingest_config_from_file(conf_files):
    """
        pull in config variables from a system file
    """
    config = configparser.ConfigParser()
    for filename in conf_files:
        if os.path.isfile(filename):
            try:
                config.read(filename)
                break
            except (configparser.Error):
                pass
    else:
        # We deliberately fail out here rather than try to
        # exit gracefully, because we are severely misconfig'ed.
        raise IOError('Config file not found')
    return config

def main_work(argv):
    """
        Print the config that should go to each client into a file.
        Return True on success, False upon failure.
        Side effect is that we write to the output_filename.
    """
    parser = ArgumentParser(description='Args for client-disconnect')
    parser.add_argument('--conf', type=str, required=True,
                        help='Config file',
                        dest='conffile', default=None)
    args = parser.parse_args(argv[1:])

    if args.conffile is not None:
        config = _ingest_config_from_file([args.conffile])

        try:
            metrics_log_dir = config.get('client-disconnect',
                                         'metrics-log-dir')
        except (configparser.NoOptionError, configparser.NoSectionError):
            metrics_log_dir = ''
        if not (os.path.isdir(metrics_log_dir) and
                os.access(metrics_log_dir, os.W_OK)):
            metrics_log_dir = None

        try:
            metrics_requested = set(ast.literal_eval(
                config.get('client-disconnect', 'metrics')))
        except:  # pragma: no cover  pylint: disable=bare-except
            # This bare-except is due to 2.7 limitations in configparser.
            metrics_requested = set()
        if not isinstance(metrics_requested, set):  # pragma: no cover
            metrics_requested = set()

        try:
            event_send = config.getboolean('client-disconnect',
                                           'syslog-events-send')
        except (configparser.NoOptionError, configparser.NoSectionError):
            event_send = False

        try:
            _base_facility = config.get('client-disconnect',
                                        'syslog-events-facility')
        except (configparser.NoOptionError, configparser.NoSectionError):
            _base_facility = 'auth'
        try:
            event_facility = getattr(syslog, 'LOG_{}'.format(_base_facility.upper()))
        except (AttributeError):
            event_facility = syslog.LOG_AUTH

    # common_name is an environmental variable passed in:
    # "The X509 common name of an authenticated client."
    # https://openvpn.net/index.php/open-source/documentation/manuals/65-openvpn-20x-manpage.html
    usercn = os.environ.get('common_name')
    trusted_ip = os.environ.get('trusted_ip')

    if not usercn:
        # alternately, "The username provided by a connecting client."
        usercn = os.environ.get('username')

    # Super failure in openvpn, or hacking, or an improper test from a human.
    if not usercn:
        print('No common_name or username environment variable provided.')
        return False
    if not trusted_ip:
        print('No trusted_ip environment variable provided.')
        return False

    log_metrics_to_disk(usercn, metrics_log_dir, metrics_requested)
    if event_send:
        log_event(usercn, event_facility)
    return True

def main():
    """ Interface to the outside """
    if main_work(sys.argv):
        sys.exit(0)
    sys.exit(1)

if __name__ == '__main__':  # pragma: no cover
    main()
