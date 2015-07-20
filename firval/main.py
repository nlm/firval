import sys
import yaml
import argparse

from voluptuous import MultipleInvalid
from .exception import ConfigError, ParseError
from .core import Firval

def main():
    """
    command-line version of the lib
    """
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('file', type=str, nargs='?', default='-',
                            help='a yaml rules file')
        args = parser.parse_args()
        if args.file == '-':
            print(str(Firval(yaml.load(sys.stdin))))
        else:
            with open(args.file, 'r') as fd:
                print(str(Firval(yaml.load(fd))))
    except yaml.parser.ParserError as ex:
        print("# firval: yaml parsing error: " + str(ex).replace("\n", ""))
    except MultipleInvalid as ex:
        print("# firval: config structure error: " + str(ex).replace("\n", ""))
    except ParseError as ex:
        print("# firval: rule parsing error: " + str(ex).replace("\n", ""))
    except ConfigError as ex:
        print("# firval: config error: " + str(ex).replace("\n", ""))
    except KeyboardInterrupt as ex:
        print("# firval: keyboard interrupt")
#    except Exception as ex:
#        print("# firval: error: " + str(ex).replace("\n", ""))
