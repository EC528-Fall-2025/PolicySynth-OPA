import unittest
from unittest.mock import Mock, patch
from argparse import Namespace

from cli import main


class TestCLIMain(unittest.TestCase):
    def test_main_dispatches_fetch_scp(self):
        handler = Mock()
        args = Namespace(command='fetch-scp', func=handler)

        with patch('argparse.ArgumentParser.parse_args', return_value=args):
            main()

        handler.assert_called_once_with(args)

    def test_main_missing_command_shows_help_and_exits(self):
        args = Namespace(command=None)

        with patch('argparse.ArgumentParser.parse_args', return_value=args), \
             patch('argparse.ArgumentParser.print_help') as print_help_mock, \
             patch('cli.sys.exit', side_effect=SystemExit(1)) as exit_mock:
            with self.assertRaises(SystemExit):
                main()

        print_help_mock.assert_called_once()
        exit_mock.assert_called_once_with(1)
