"""
    Script to report on disconnecting VPN clients
"""
import os
import sys
import ast
import time
import json
from argparse import ArgumentParser
import mozdef_client_config
sys.dont_write_bytecode = True
try:
    import configparser
except ImportError:  # pragma: no cover
    from six.moves import configparser


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


def log_to_mozdef(usercn, log_to_stdout):
    """
        Gather the metrics we have in the environment,
        send a disconnect event to mozdef.
        Maybe also log it to stdout.
    """
    quick_metrics = {'sourceipaddress': os.environ.get('trusted_ip', ''),
                     'sourceport': os.environ.get('trusted_port', ''),
                     'vpnip': os.environ.get('ifconfig_pool_remote_ip', ''),
                     'username': usercn,
                     'connectionduration': os.environ.get('time_duration', ''),
                     'bytessent': os.environ.get('bytes_sent', ''),
                     'bytesreceived': os.environ.get('bytes_received', ''),
                     'success': 'true'}

    logger = mozdef_client_config.ConfigedMozDefEvent()
    # While 'authorization' might seem more correct (we are layering
    # access upon a user after they have been authenticated), we are
    # asked to put all login-related info under the category of
    # 'authentication'.  So, don't change this without an EIS consult.
    logger.category = 'authentication'
    logger.source = 'openvpn'
    logger.tags = ['vpn', 'disconnect']

    logger.summary = ('SUCCESS: VPN disconnection for '
                      '{}'.format(usercn))
    logger.details = quick_metrics
    logger.send()
    if log_to_stdout:
        print(logger.syslog_convert())

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

def main(argv):
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

        # We use mozdef to log about activities.  However, for triage,
        # it is in our interest to keep records, real-time, on the server.
        # mozdef can do syslog, but that is a separate file from the vpn's
        # activity log.  So, to put it all in one place, we can log to
        # stdout.
        try:
            log_to_stdout = config.getboolean('client-disconnect',
                                              'log-to-stdout')
        except (configparser.NoOptionError, configparser.NoSectionError):
            log_to_stdout = False

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
    log_to_mozdef(usercn, log_to_stdout)
    return True


if __name__ == '__main__':  # pragma: no cover
    if main(sys.argv):
        sys.exit(0)
    sys.exit(1)
