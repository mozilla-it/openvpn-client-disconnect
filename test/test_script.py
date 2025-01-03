""" openvpn-disconnect test script """

import unittest
import os
from io import StringIO
import syslog
import datetime
import json
import configparser
import test.context  # pylint: disable=unused-import
import mock
import openvpn_client_disconnect


class TestClientDisconnect(unittest.TestCase):
    """
        Coverage test for the openvpn script that starts all this.
    """
    #openvpn_client_disconnect = import_path('scripts/openvpn-client-disconnect')

    def setUp(self):
        """ Create the library """
        self.openvpn_client_disconnect = openvpn_client_disconnect

    def tearDown(self):
        """ Clear the env so we don't impact other tests """
        for varname in ['common_name', 'time_unix', 'trusted_ip',
                        'something1', 'something2', 'password']:
            if varname in os.environ:
                del os.environ[varname]

    def test_03_ingest_no_config_files(self):
        """ With no config files, get an empty ConfigParser """
        with self.assertRaises(IOError), \
                mock.patch('sys.stderr', new=StringIO()):
            self.openvpn_client_disconnect._ingest_config_from_file([])

    def test_04_ingest_no_config_file(self):
        """ With all missing config files, get an empty ConfigParser """
        with self.assertRaises(IOError), \
                mock.patch('sys.stderr', new=StringIO()):
            _not_a_real_file = '/tmp/no-such-file.txt'  # nosec hardcoded_tmp_directory
            self.openvpn_client_disconnect._ingest_config_from_file([_not_a_real_file])

    def test_05_ingest_bad_config_file(self):
        """ With a bad config file, get an empty ConfigParser """
        with self.assertRaises(IOError), \
                mock.patch('sys.stderr', new=StringIO()):
            self.openvpn_client_disconnect._ingest_config_from_file(['test/context.py'])

    def test_06_ingest_config_from_file(self):
        """ With an actual config file, get a populated ConfigParser """
        test_reading_file = '/tmp/test-reader.txt'  # nosec hardcoded_tmp_directory
        with open(test_reading_file, 'w', encoding='utf-8') as filepointer:
            filepointer.write('[aa]\nbb = cc\n')
        filepointer.close()
        result = self.openvpn_client_disconnect._ingest_config_from_file([test_reading_file])
        os.remove(test_reading_file)
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), ['aa'],
                         'Should have found one configfile section.')
        self.assertEqual(result.options('aa'), ['bb'],
                         'Should have found one option.')
        self.assertEqual(result.get('aa', 'bb'), 'cc',
                         'Should have read a correct value.')

    def test_10_log_metrics_to_disk(self):
        """ Validate that log_metrics_to_disk does the right things. """
        # common_name, time_unix = always shared
        # something1             = shared because we ask for it
        # something2             = present but not shared
        # password               = never should be shared
        os.environ['common_name'] = 'bob-device'
        os.environ['time_unix'] = '1591193143'
        os.environ['something1'] = 'foo'
        os.environ['something2'] = 'bar'
        os.environ['password'] = 'hunter2'  # nosec hardcoded_password_string
        with mock.patch('openvpn_client_disconnect.open', create=True,
                        return_value=mock.MagicMock(spec=StringIO())) as mock_open:
            _tmp_dir = '/tmp'  # nosec hardcoded_tmp_directory
            self.openvpn_client_disconnect.log_metrics_to_disk('bob', _tmp_dir,
                                                               set(['common_name', 'time_unix',
                                                                    'something1', 'password']))
        file_handle = mock_open.return_value.__enter__.return_value
        expected_response = ('{\n'
                             '  "common_name": "bob-device",\n'
                             '  "something1": "foo",\n'
                             '  "time_unix": "1591193143"\n'
                             '}\n')
        file_handle.write.assert_called_with(expected_response)

    def test_11_log_event(self):
        """ Validate that log_event does the right things. """
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(2020, 12, 25, 13, 14, 15,
                                                           123456, tzinfo=datetime.timezone.utc)
        os.environ['trusted_ip'] = '1.2.3.4'
        os.environ['trusted_port'] = '9999'
        os.environ['ifconfig_pool_remote_ip'] = '192.168.50.2'
        os.environ['time_duration'] = '300'
        os.environ['bytes_sent'] = '34'
        os.environ['bytes_received'] = '1234'
        with mock.patch('syslog.openlog') as mock_openlog, \
                mock.patch('syslog.syslog') as mock_syslog, \
                mock.patch('datetime.datetime', new=datetime_mock), \
                mock.patch('os.getpid', return_value=12345), \
                mock.patch('socket.getfqdn', return_value='my.host.name'):
            self.openvpn_client_disconnect.log_event('someone@example.com', syslog.LOG_LOCAL0)
        mock_openlog.assert_called_once_with(facility=syslog.LOG_LOCAL0)
        mock_syslog.assert_called_once()
        arg_passed_in = mock_syslog.call_args_list[0][0][0]
        json_sent = json.loads(arg_passed_in)
        details = json_sent['details']
        self.assertEqual(json_sent['category'], 'authentication')
        self.assertEqual(json_sent['processid'], 12345)
        self.assertEqual(json_sent['severity'], 'INFO')
        self.assertIn('processname', json_sent)
        self.assertEqual(json_sent['timestamp'], '2020-12-25T13:14:15.123456+00:00')
        self.assertEqual(json_sent['hostname'], 'my.host.name')
        self.assertEqual(json_sent['summary'], 'SUCCESS: VPN disconnection for someone@example.com')
        self.assertEqual(json_sent['source'], 'openvpn')
        self.assertEqual(json_sent['tags'], ['vpn', 'disconnect'])
        self.assertEqual(details['username'], 'someone@example.com')
        self.assertEqual(details['bytesreceived'], '1234')
        self.assertEqual(details['bytessent'], '34')
        self.assertEqual(details['vpnip'], '192.168.50.2')
        self.assertEqual(details['sourceport'], '9999')
        self.assertEqual(details['connectionduration'], '300')
        self.assertEqual(details['sourceipaddress'], '1.2.3.4')
        self.assertEqual(details['success'], 'true')

    def test_20_main_main(self):
        ''' Test the main() interface '''
        with self.assertRaises(SystemExit) as exiting, \
                mock.patch.object(self.openvpn_client_disconnect, 'main_work',
                                  return_value=True):
            self.openvpn_client_disconnect.main()
        self.assertEqual(exiting.exception.code, 0)
        with self.assertRaises(SystemExit) as exiting, \
                mock.patch.object(self.openvpn_client_disconnect, 'main_work',
                                  return_value=False):
            self.openvpn_client_disconnect.main()
        self.assertEqual(exiting.exception.code, 1)

    def test_20_main_blank(self):
        ''' With no conf file provided, bomb out '''
        with self.assertRaises(SystemExit) as exiting, \
                mock.patch('sys.stderr', new=StringIO()):
            self.openvpn_client_disconnect.main_work([])
        self.assertEqual(exiting.exception.code, 2)

    def test_21_main_with_bad_confs(self):
        ''' With bad conf files, bomb out '''
        with self.assertRaises(IOError), \
                mock.patch('sys.stderr', new=StringIO()):
            _not_a_real_file = '/tmp/no-such-file.txt'  # nosec hardcoded_tmp_directory
            self.openvpn_client_disconnect.main_work(['script', '--conf', _not_a_real_file])

        with self.assertRaises(IOError), \
                mock.patch('sys.stderr', new=StringIO()):
            self.openvpn_client_disconnect.main_work(['script', '--conf', 'test/context.py'])

    def test_22_main_blank(self):
        ''' With envvars provided, bomb out '''
        config = configparser.ConfigParser()
        with mock.patch.object(self.openvpn_client_disconnect, '_ingest_config_from_file',
                               return_value=config), \
                mock.patch('sys.stdout', new=StringIO()) as fake_out:
            result = self.openvpn_client_disconnect.main_work(['script', '--conf',
                                                               'test/context.py'])
        self.assertFalse(result, 'With no environmental variables, main_work must fail')
        self.assertIn('No common_name or username environment variable provided.',
                      fake_out.getvalue())

    def test_23_incomplete_vars(self):
        ''' With just one envvar provided, bomb out '''
        os.environ['common_name'] = 'bob-device'
        config = configparser.ConfigParser()
        with mock.patch.object(self.openvpn_client_disconnect, '_ingest_config_from_file',
                               return_value=config), \
                mock.patch('sys.stdout', new=StringIO()) as fake_out:
            result = self.openvpn_client_disconnect.main_work(['script', '--conf',
                                                               'test/context.py'])
        self.assertFalse(result, 'With not-all environmental variables, main_work must fail')
        self.assertIn('No trusted_ip environment variable provided.', fake_out.getvalue())

    def test_24_complete_vars_default(self):
        ''' Run correctly with defaults. '''
        os.environ['common_name'] = 'bob-device'
        os.environ['trusted_ip'] = '10.20.30.40'
        config = configparser.ConfigParser()
        with mock.patch.object(self.openvpn_client_disconnect, '_ingest_config_from_file',
                               return_value=config), \
                mock.patch.object(self.openvpn_client_disconnect,
                                  'log_metrics_to_disk') as mock_metrics, \
                mock.patch.object(self.openvpn_client_disconnect,
                                  'log_event') as mock_logevent:
            result = self.openvpn_client_disconnect.main_work(['script', '--conf',
                                                               'test/context.py'])
        self.assertTrue(result, 'With all environmental variables, main_work must work')
        mock_metrics.assert_called_once_with('bob-device', None, set([]))
        mock_logevent.assert_not_called()

    def test_25_complete_with_logging(self):
        ''' Run with terrible logging settings. '''
        os.environ['common_name'] = 'bob-device'
        os.environ['trusted_ip'] = '10.20.30.40'
        config = configparser.ConfigParser()
        config.add_section('client-disconnect')
        config.set('client-disconnect', 'syslog-events-send', 'true')
        config.set('client-disconnect', 'syslog-events-facility', 'invalid')
        with mock.patch.object(self.openvpn_client_disconnect, '_ingest_config_from_file',
                               return_value=config), \
                mock.patch.object(self.openvpn_client_disconnect,
                                  'log_metrics_to_disk') as mock_metrics, \
                mock.patch.object(self.openvpn_client_disconnect,
                                  'log_event') as mock_logevent:
            result = self.openvpn_client_disconnect.main_work(['script', '--conf',
                                                               'test/context.py'])
        self.assertTrue(result, 'With all environmental variables, main_work must work')
        mock_metrics.assert_called_once_with('bob-device', None, set([]))
        mock_logevent.assert_called_once_with('bob-device', syslog.LOG_AUTH)

    def test_26_complete_with_logging(self):
        ''' Run correctly with logging enabled. '''
        os.environ['common_name'] = 'bob-device'
        os.environ['trusted_ip'] = '10.20.30.40'
        config = configparser.ConfigParser()
        config.add_section('client-disconnect')
        config.set('client-disconnect', 'syslog-events-send', 'true')
        config.set('client-disconnect', 'syslog-events-facility', 'mail')
        with mock.patch.object(self.openvpn_client_disconnect, '_ingest_config_from_file',
                               return_value=config), \
                mock.patch.object(self.openvpn_client_disconnect,
                                  'log_metrics_to_disk') as mock_metrics, \
                mock.patch.object(self.openvpn_client_disconnect,
                                  'log_event') as mock_logevent:
            result = self.openvpn_client_disconnect.main_work(['script', '--conf',
                                                               'test/context.py'])
        self.assertTrue(result, 'With all environmental variables, main_work must work')
        mock_metrics.assert_called_once_with('bob-device', None, set([]))
        mock_logevent.assert_called_once_with('bob-device', syslog.LOG_MAIL)
