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
        parser = argparse.ArgumentParser()
        parser.add_argument('file', type=str, nargs='?', default='-',
                            help='a yaml rules file')
        parser.add_argument('-d', '--debug', action='store_true', default=False,
                            help='debug mode')
        args = parser.parse_args()
        if args.file == '-':
            print(str(Firval(yaml.load(sys.stdin))))
        else:
            with open(args.file, 'r') as fde:
                print(str(Firval(yaml.load(fde))))
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
        if args.debug:
            raise
        print('# firval: error: {0}: {1}' \
              .format(type(ex), str(ex).replace("\n", "")))
