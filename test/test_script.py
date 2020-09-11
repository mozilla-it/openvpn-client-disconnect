""" openvpn-disconnect test script """

import unittest
import os
import sys
import test.context  # pylint: disable=unused-import
import configparser
import mock
import openvpn_client_disconnect
if sys.version_info.major >= 3:
    from io import StringIO  # pragma: no cover
else:
    from io import BytesIO as StringIO  # pragma: no cover


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
            self.openvpn_client_disconnect._ingest_config_from_file(['/tmp/no-such-file.txt'])

    def test_05_ingest_bad_config_file(self):
        """ With a bad config file, get an empty ConfigParser """
        with self.assertRaises(IOError), \
                mock.patch('sys.stderr', new=StringIO()):
            self.openvpn_client_disconnect._ingest_config_from_file(['test/context.py'])

    def test_06_ingest_config_from_file(self):
        """ With an actual config file, get a populated ConfigParser """
        test_reading_file = '/tmp/test-reader.txt'
        with open(test_reading_file, 'w') as filepointer:
            filepointer.write('[aa]\nbb = cc\n')
        filepointer.close()
        result = self.openvpn_client_disconnect._ingest_config_from_file(['/tmp/test-reader.txt'])
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
        os.environ['password'] = 'hunter2'
        with mock.patch('openvpn_client_disconnect.open', create=True,
                        return_value=mock.MagicMock(spec=StringIO())) as mock_open:
            self.openvpn_client_disconnect.log_metrics_to_disk('bob', '/tmp',
                                                               set(['common_name', 'time_unix',
                                                                    'something1', 'password']))
        file_handle = mock_open.return_value.__enter__.return_value
        # This test fails under py2 for spacing reason but is otherwise good.
        # Bring back when we drop py2 support:
        #expected_response = ('{\n'
        #                     '  "common_name": "bob-device",\n'
        #                     '  "something1": "foo",\n'
        #                     '  "time_unix": "1591193143"\n'
        #                     '}\n')
        #file_handle.write.assert_called_with(expected_response)
        file_handle.write.assert_called_once()

    def test_11_log_to_mozdef(self):
        """ Validate that log_to_mozdef does the right things. """
        with mock.patch('mozdef_client_config.ConfigedMozDefEvent') as mock_logger:
            instance = mock_logger.return_value
            with mock.patch.object(instance, 'send') as mock_send, \
                    mock.patch.object(instance, 'syslog_convert', return_value='msg1'), \
                    mock.patch('sys.stdout', new=StringIO()) as fake_out:
                self.openvpn_client_disconnect.log_to_mozdef('blah1', True)

        self.assertEqual(instance.category, 'authentication')
        self.assertEqual(instance.source, 'openvpn')
        self.assertIn('vpn', instance.tags)
        self.assertIn('blah1', instance.summary)
        self.assertEqual(instance.details['username'], 'blah1')
        self.assertEqual(instance.details['success'], 'true')
        mock_send.assert_called_once_with()
        # This is a dumb test: we are just validating that syslog_convert was called:
        self.assertIn('msg1', fake_out.getvalue())

    def test_20_main_blank(self):
        ''' With no conf file provided, bomb out '''
        with self.assertRaises(SystemExit) as exiting, \
                mock.patch('sys.stderr', new=StringIO()):
            self.openvpn_client_disconnect.main([])
        self.assertEqual(exiting.exception.code, 2)

    def test_21_main_with_bad_confs(self):
        ''' With bad conf files, bomb out '''
        with self.assertRaises(IOError), \
                mock.patch('sys.stderr', new=StringIO()):
            self.openvpn_client_disconnect.main(['script', '--conf', '/tmp/nofile'])

        with self.assertRaises(IOError), \
                mock.patch('sys.stderr', new=StringIO()):
            self.openvpn_client_disconnect.main(['script', '--conf', 'test/context.py'])

    def test_22_main_blank(self):
        ''' With envvars provided, bomb out '''
        config = configparser.ConfigParser()
        with mock.patch.object(self.openvpn_client_disconnect, '_ingest_config_from_file',
                               return_value=config), \
                mock.patch('sys.stdout', new=StringIO()) as fake_out:
            result = self.openvpn_client_disconnect.main(['script', '--conf', 'test/context.py'])
        self.assertFalse(result, 'With no environmental variables, main must fail')
        self.assertIn('No common_name or username environment variable provided.',
                      fake_out.getvalue())

    def test_23_incomplete_vars(self):
        ''' With just one envvar provided, bomb out '''
        os.environ['common_name'] = 'bob-device'
        config = configparser.ConfigParser()
        with mock.patch.object(self.openvpn_client_disconnect, '_ingest_config_from_file',
                               return_value=config), \
                mock.patch('sys.stdout', new=StringIO()) as fake_out:
            result = self.openvpn_client_disconnect.main(['script', '--conf', 'test/context.py'])
        self.assertFalse(result, 'With not-all environmental variables, main must fail')
        self.assertIn('No trusted_ip environment variable provided.', fake_out.getvalue())

    def test_24_complete_vars(self):
        ''' Run correctly. '''
        os.environ['common_name'] = 'bob-device'
        os.environ['trusted_ip'] = '10.20.30.40'
        config = configparser.ConfigParser()
        with mock.patch.object(self.openvpn_client_disconnect, '_ingest_config_from_file',
                               return_value=config), \
                mock.patch.object(self.openvpn_client_disconnect,
                                  'log_metrics_to_disk') as mock_metrics, \
                mock.patch.object(self.openvpn_client_disconnect,
                                  'log_to_mozdef') as mock_mozdef:
            result = self.openvpn_client_disconnect.main(['script', '--conf', 'test/context.py'])
        self.assertTrue(result, 'With all environmental variables, main must work')
        mock_metrics.assert_called_once_with('bob-device', None, set([]))
        mock_mozdef.assert_called_once_with('bob-device', False)
