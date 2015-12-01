"""
Command-line for firval
"""
from __future__ import print_function, absolute_import

import sys
import yaml
import argparse

from voluptuous import MultipleInvalid
from .exception import ConfigError, ParseError
from .core import Firval


def main():
    """
    main command-line interface
    """
    try:
        debug = True
        parser = argparse.ArgumentParser()
        parser.add_argument('config_file', type=str, default='-', nargs='?',
                            help='a yaml config file')
        parser.add_argument('-d', '--debug', action='store_true', default=False,
                            help='debug mode')
        parser.add_argument('-o', '--output', default='-', metavar='output_file',
                            help='output file (default: stdout)')
        args = parser.parse_args()
        debug = args.debug

        rfd = sys.stdin if args.config_file == '-' else open(args.config_file, 'r')
        wfd = sys.stdout if args.output == '-' else open(args.output, 'w')
        print(str(Firval(yaml.safe_load(rfd))), file=wfd)
        rfd.close()
        wfd.close()

    except yaml.parser.ParserError as ex:
        print('# firval: yaml parsing error: {0}' \
              .format(str(ex).replace("\n", "")))
    except MultipleInvalid as ex:
        print('# firval: config structure error: {0}' \
              .format(str(ex).replace("\n", "")))
    except ParseError as ex:
        print('# firval: rule parsing error: {0}' \
              .format(str(ex).replace("\n", "")))
    except ConfigError as ex:
        print('# firval: config error: {0}' \
              .format(str(ex).replace("\n", "")))
    except KeyboardInterrupt as ex:
        print('# firval: keyboard interrupt')
    except Exception as ex:
        if debug:
            raise
        print('# firval: error: {0}: {1}' \
              .format(type(ex), str(ex).replace("\n", "")))
