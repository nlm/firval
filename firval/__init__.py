"""
firval
======

a netfilter firewall rules generator designed
to be easy to read, write and maintain

How to use
==========

Write a yaml configuration file and feed it to firval,
it will produce a iptables-restore compatible rule file

it means you can do this:

    cat rules.yaml | firval | iptables-restore

Configuration syntax
====================

    interfaces:
      IFNAME: PHYSICALINTERFACE

    addresses:
      ADDRNAME: HOSTADDR | NETADDR

    ports:
      PORTNAME: PORTNUMBER

    chains:
      filter|nat|mangle:
        CHAINNAME:
          - RULE
          - ...

    services:
      SERVICENAME:
        proto: tcp | udp | icmp
        port: PORT-NUMBER(,PORT-NUMBER)* (only for tcp or udp)
        type: ICMP-TYPE (only for icmp)

    rulesets:
      IFNAME-to-IFNAME:
        filter|nat|mangle:
          input|forward|output|...: (availability depends if in 'filter', 'nat' or 'mangle')
            - RULE
            - ...

    RULE = ((accept|reject|drop|masquerade|log|nflog)
            ((not)? from ADDRNAME ((not)? port PORTNAME)?)?
            ((not)? to ADDRNAME ((not)? port PORTNAME)?)?
            ((not)? proto (tcp|udp|icmp|any))?
            (service SERVICENAME)?
            (state (new|established|invalid))?
            (limit INTEGER/TIMEUNIT (burst INTEGER)?)?
            (comment "COMMENT")?
            (prefix "LOG_PREFIX"))
            | (jump CHAINNAME)

"""
import sys
import re
import datetime
from voluptuous import Schema, Required, Optional, Any, All, Invalid, Match, In
from voluptuous import MultipleInvalid
from netaddr import IPNetwork
import yaml
import argparse

class ConfigError(Exception):
    """
    Exception for Configuration Errors
    """
    pass

class ParseError(Exception):
    """
    Exception for Parsing Errors
    """
    pass

class Firval(object):
    """
    The main Firval class
    """
    _re = {
        'obj': '^[a-zA-Z0-9-_]{1,128}$',
        'zone': '^[a-z0-9]+$',
        'if': '^[a-z0-9:.]+$',
        'ruleset': '^[a-z0-9_]+-to-[a-z0-9_]+$',
    }

    protocols = ('tcp', 'udp', 'icmp')

    icmp_types = ('echo-reply', 'pong', 'destination-unreachable',
                  'network-unreachable', 'host-unreachable',
                  'protocol-unreachable', 'port-unreachable',
                  'fragmentation-needed', 'source-route-failed',
                  'network-unknown', 'host-unknown', 'network-prohibited',
                  'host-prohibited', 'TOS-network-unreachable',
                  'TOS-host-unreachable', 'communication-prohibited',
                  'host-precedence-violation', 'precedence-cutoff',
                  'source-quench', 'redirect', 'network-redirect',
                  'host-redirect', 'TOS-network-redirect', 'TOS-host-redirect',
                  'echo-request', 'ping', 'router-advertisement',
                  'router-solicitation', 'time-exceeded', 'ttl-exceeded',
                  'ttl-zero-during-transit', 'ttl-zero-during-reassembly',
                  'parameter-problem', 'ip-header-bad',
                  'required-option-missing', 'timestamp-request',
                  'timestamp-reply', 'address-mask-request',
                  'address-mask-reply')

    _syschains = {
        'filter': ('input', 'forward', 'output'),
        'nat': ('prerouting', 'input', 'output', 'postrouting'),
        'mangle': ('prerouting', 'input', 'forward', 'output', 'postrouting')
    }

    def __init__(self, obj):
        """
        initializes the object

        parameters:
            obj: the datastructure representing the rules
        """
        self.chains = []
        self.data = self.validate(obj)

    def _get_iface(self, name):
        """
        get an interface name from config

        parameters:
            name: the symbolic interface name

        returns:
            the physical interface name
        """
        try:
            return self.data['interfaces'][name]
        except KeyError:
            return None

    @staticmethod
    def _valid_addr(address):
        """
        object for voluptuous syntax validation

        parameters:
            address: an IP address or network

        returns:
            an IPNetwork object
        """
        return IPNetwork(address)

    @classmethod
    def validate(cls, data):
        """
        validates the data schema

        parameters:
            data: the data structure to validate

        returns:
            the validated data structure
        """
        Schema({
            Required('interfaces'): {
                All(str, Match(cls._re['obj'])):
                    All(str, Match(cls._re['if']))
            },
            Optional('addresses'): {
                All(str, Match(cls._re['obj'])):
                    All(str, cls._valid_addr)
            },
            Optional('ports'): {
                All(str, Match(cls._re['obj'])):
                    All(int)
            },
            Optional('services'): {
                All(str, Match(cls._re['obj'])): {
                    Required('proto'): All(str, In(cls.protocols)),
                    'port': Any(int,
                                Match(r'^[a-z-]+$'),
                                Match(r'^\d+(,\d+)*$')),
                    'type': All(str, In(cls.icmp_types)),
                }
            },
            Optional('chains'): {
                All(str, In(cls._syschains.keys())): {
                    All(str, Match(cls._re['obj'])):
                        [All(str, Match(Rule.pattern))]
                }
            },
            'rulesets': {
                All(str, Match(cls._re['ruleset'])): {
                    'filter': {
                        All(str, In(cls._syschains['filter'])):
                            [All(str, Match(Rule.pattern))],
                    },
                    'nat': {
                        All(str, In(cls._syschains['nat'])):
                            [All(str, Match(Rule.pattern))],
                    },
                    'mangle': {
                        All(str, In(cls._syschains['mangle'])):
                            [All(str, Match(Rule.pattern))],
                    }
                }
            }
        })(data)
        return data

    def __str__(self):
        """
        prints the rules represented by this object

        returns:
            string reprentation of the ruleset
        """
        data = self.data
        lne = []
        if 'rulesets' not in data:
            return ""

        rules = {}
        routing = {}
        custchains = {}

        # Rulesets Generation #################################################
        for ruleset in data['rulesets']:

            # Interfaces  #####################################################
            (izone, ozone) = re.match(r'^(\S+)-to-(\S+)$', ruleset).groups()

            if izone == 'any':
                iif = None
            else:
                iif = self._get_iface(izone)
                if iif is None:
                    raise ConfigError("{0} interface is not defined".format(izone))

            if ozone == 'any':
                oif = None
            else:
                oif = self._get_iface(ozone)
                if oif is None:
                    raise ConfigError("{0} interface is not defined".format(ozone))

            # Tables ##########################################################
            for table in data['rulesets'][ruleset]:

                if table not in rules:
                    rules[table] = {}

                if table not in routing:
                    routing[table] = {}

                # Chains ######################################################
                for chain in data['rulesets'][ruleset][table]:

                    # Routing #################################################

                    if chain not in routing[table]:
                        routing[table][chain] = []

                    rule = ['-A', chain.upper()]

                    if iif is not None:
                        rule.extend(['-i', iif])
                    if oif is not None:
                        rule.extend(['-o', oif])

                    rule.extend(['-j', '{0}-{1}'.format(chain, ruleset).lower()])
                    rule.extend(['-m', 'comment'])
                    rule.extend(['--comment', '"{0} {1} -> {2}"'.format(chain, izone, ozone)])

                    rulestr = ' '.join(rule)

                    # default rule comes last
                    if iif is None and oif is None:
                        routing[table][chain].append(rulestr)
                    elif iif is None or oif is None:
                        routing[table][chain].insert(
                            len(routing[table][chain]) - 1, rulestr)
                    else:
                        routing[table][chain].insert(0, rulestr)

                    # Rules ###################################################
                    if chain not in rules[table]:
                        rules[table][chain] = {}

                    rules[table][chain][ruleset] = []

                    for rule in data['rulesets'][ruleset][table][chain]:
                        rules[table][chain][ruleset].append('-A {0}-{1} {2}'.format(chain.lower(), ruleset.lower(), str(Rule(rule, aliases=self.data, table=table))))

        # Custom Chains Generation ############################################

        if 'chains' in data:
            for table in data['chains']:
                custchains[table] = {}
                for chain in data['chains'][table]:
                    custchains[table][chain] = []
                    for rule in data['chains'][table][chain]:
                        custchains[table][chain].append('-A custom-{0} {1}'.format(chain.lower(), str(Rule(rule, aliases=self.data, table=table))))

        # Rules Output ########################################################

        lne = ['# generated by firval {0}'.format(datetime.datetime.now())]

        # Tables ##############################################################
        for table in rules:
            if len(lne) > 1:
                lne.append("COMMIT")
            lne.append("*{0}".format(table))

            # system chains
            for chain in self._syschains[table]:
                lne.append(':{0} ACCEPT [0:0]'.format(chain.upper()))

            # custom routing chains
            for chain in rules[table]:
                for ruleset in rules[table][chain]:
                    lne.append(':{0}-{1} - [0:0]'.format(chain.lower(), ruleset.lower()))

            # custom chains
            if table in custchains:
                for chain in custchains[table]:
                    lne.append(':custom-{0} - [0:0]'.format(chain.lower()))

            # routing rules
            for chain in routing[table]:
                for rule in routing[table][chain]:
                    lne.append(rule)

            # chain rules
            for chain in rules[table]:
                for ruleset in rules[table][chain]:
                    for rule in rules[table][chain][ruleset]:
                        lne.append(rule)

            # custom chain rules
            if table in custchains:
                for chain in custchains[table]:
                    for rule in custchains[table][chain]:
                        lne.append(rule)

        lne.append('COMMIT')
        lne.append('# finished {0}'.format(datetime.datetime.now()))
        return "\n".join(lne)


class Rule():
    """
    object representing an iptables rule
    """
    pattern = r'^\s*(' + \
        r'(jump\s+(?P<jump_chain>\S+))|' + \
        r'(?P<clampmss>clampmss)|' + \
        r'(?P<setmss>setmss\s+(?P<max_mss>\d+))|' + \
        r'(?P<action>accept|reject|drop|masquerade|log|nflog)' + \
        r'(?:(?:\s+(?P<src_neg>not))?\s+from\s+(?P<src_addr>\S+)' + \
        r'(?:(?:\s+(?P<src_port_neg>not))?\s+port\s+(?P<src_port>\S+))?)?' + \
        r'(?:(?:\s+(?P<dst_neg>not))?\s+to\s+(?P<dst_addr>\S+)' + \
        r'(?:(?:\s+(?P<dst_port_neg>not))?\s+port\s+(?P<dst_port>\S+))?)?' + \
        r'(?:(?:\s+(?P<proto_neg>not))?\s+proto\s+(?P<proto>tcp|udp|icmp|any))?' + \
        r'(?:(?:\s+(?P<icmp_type_neg>not))?\s+type\s+(?P<icmp_type>\S+))?' + \
        r'(?:\s+service\s+(?P<service>\S+))?' + \
        r'(?:\s+state\s+(?P<state>new|established|invalid))?' + \
        r'(?:\s+limit\s+(?P<limit>\d+/\S)(?:\s+burst\s+(?P<limit_burst>\S+))?)?' + \
        r'(?:\s+comment\s+(?P<comment>"[^"]+"))?' + \
        r'(?:\s+prefix\s+(?P<log_prefix>"[^"]*"))?' + \
        r')\s*$'

    def __init__(self, text, aliases=None, table=None):
        """
        initializes the Rule object

        parameters:
            text: the rule written with firval simplified syntax
            aliases: address, ports, services and chains dictionnary
            table: chains dictionnary for chain jumping
        """
        self.comment = None
        self.data = None
        self._text = text
        self._aliases = aliases if aliases is not None else {}
        self._table = table if table is not None else ''
        self.data = self.parse(text)

    def __getattr__(self, name):
        """
        retrieves an internal attribute

        parameters:
            name: the attribute name

        returns:
            the attribute value or None if not found
        """
        if self.data is not None and name in self.data:
            return self.data[name]
        return None

    @classmethod
    def parse(cls, text):
        """
        parse some text and return an attribute dict

        parameters:
            text: the rule text in firval language

        returns:
            an attribute dictionnary
        """
        result = re.match(cls.pattern, text)
        if result:
            return result.groupdict()
        else:
            raise ParseError(text)

    @staticmethod
    def _is_any(value):
        """
        check if a value is 'any' or equivalent (None)

        parameters:
            value: the value to check

        returns:
            True or False
        """
        return value is None or value == 'any'

    def _get_address(self, name):
        """
        get an address from the address table

        parameters:
            name: the name associated with the address

        returns:
            the address associated with the name
        """
        try:
            return self._aliases['addresses'][name]
        except KeyError:
            return name

    def _get_port(self, name):
        """
        get a port from the port table

        parameters:
            name: the name associated with the port

        returns:
            the port associated with the name
        """
        try:
            return self._aliases['ports'][name]
        except KeyError:
            return name

    def _get_service(self, name):
        """
        get a service from the service table

        parameters:
            name: the name associated with the service

        returns:
            the service associated with the name
        """
        try:
            return self._aliases['services'][name]
        except KeyError:
            return None

    def _get_chain(self, table, name):
        """
        get a chain from the chains table

        parameters:
            table: the table in which the chain is
            name: the name associated with the chain

        returns:
            the chain associated with the name
        """
        try:
            return self._aliases['chains'][table][name]
        except KeyError:
            return None

    def __repr__(self):
        return self.__class__.__name__ + '(' + self._text + ')'

    def __str__(self):
        """
        the processed string representation of this rule

        returns:
            the string representation of this rule
        """
        rule = []

        # Source address
        if not self._is_any(self.src_addr):
            if self.src_neg is not None:
                rule.append('!')
            rule.extend(['-s', str(self._get_address(self.src_addr))])

        # Destination address
        if not self._is_any(self.dst_addr):
            if self.dst_neg is not None:
                rule.append('!')
            rule.extend(['-d', str(self._get_address(self.dst_addr))])

        # Protocol
        if not self._is_any(self.proto):
            if self.proto_neg is not None:
                rule.append('!')
            rule.extend(['-p', str(self.proto)])

        # Source port
        if not self._is_any(self.src_port):
            if self._is_any(self.proto):
                raise ConfigError("protocol must be set when using port in '{0}'".format(self._text))
            if self.src_port_neg is not None:
                rule.append('!')
            rule.extend(['--sport', str(self._get_port(self.src_port))])

        # Destination port
        if not self._is_any(self.dst_port):
            if self._is_any(self.proto):
                raise ConfigError("protocol must be set when using port in '{0}'".format(self._text))
            if self.dst_port_neg is not None:
                rule.append('!')
            rule.extend(['--dport', str(self._get_port(self.dst_port))])

        # ICMP Type
        if not self._is_any(self.icmp_type):
            if self._is_any(self.proto):
                raise ConfigError("protocol must be set when using icmp-type in '{0}'".format(self._text))
            if self.proto != 'icmp':
                raise ConfigError("protocol must be 'icmp' when using icmp-type in '{0}'".format(self._text))
            if self.icmp_type_neg is not None:
                rule.append('!')
            rule.extend(['--icmp-type', str(self.icmp_type)])

        # Service
        if self.service is not None:
            if not self._is_any(self.dst_port) or not self._is_any(self.proto):
                raise ConfigError('service conflicts with dport or proto:', self.service)
            service = self._get_service(self.service)
            if service is None:
                raise ConfigError('unknown service: ' + self.service)
            rule.extend(['-p', service['proto']])
            if service['proto'] in ['tcp', 'udp']:
                if re.match(r'^\d+(,\d+)*$', str(service['port'])):
                    ports = re.split(',', str(service['port']))
                    if len(ports) > 1:
                        rule.extend(['-m', 'multiport'])
                        rule.extend(['--dports', str(service['port'])])
                    else:
                        rule.extend(['--dport', str(service['port'])])
                else:
                    rule.extend(['--dport', str(service['port'])])

        # State
        if not self._is_any(self.state):
            if self.state == 'new':
                rule.extend(['-m', 'state', '--state', 'NEW'])
            elif self.state == 'established':
                rule.extend(['-m', 'state', '--state', 'ESTABLISHED,RELATED'])
            elif self.state == 'invalid':
                rule.extend(['-m', 'state', '--state', 'INVALID'])

        # Limit
        if self.limit is not None:
            rule.extend(['-m', 'limit', '--limit', str(self.limit)])
            if not self._is_any(self.limit_burst):
                rule.extend(['--limit-burst', str(self.limit_burst)])

        # Actions
        if self.action is not None:
            rule.extend(['-j', str(self.action.upper())])
        if self.action == 'reject':
            rule.extend(['--reject-with', 'icmp-host-prohibited'])

        # Prefix
        if self.log_prefix is not None:
            if self.action == 'log':
                rule.extend(['--log-prefix', str(self.log_prefix)])
            elif self.action == 'nflog':
                rule.extend(['--nflog-prefix', str(self.log_prefix)])
            else:
                raise ConfigError("log prefix requires 'log' or 'nflog' action")

        # Jump to custom chain
        if self.jump_chain is not None:
            if self._get_chain(self._table, self.jump_chain):
                rule.extend(['-j', 'custom-{0}'.format(self.jump_chain)])
            else:
                raise ConfigError("unknown chain: " + self.jump_chain)

        # Special Cases
        if self.clampmss is not None:
            rule.extend(['-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN'])
            rule.extend(['-j', 'TCPMSS', '--clamp-mss-to-pmtu'])
        elif self.setmss is not None:
            rule.extend(['-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN'])
            rule.extend(['-j', 'TCPMSS'])
            rule.extend(['--set-mss', '{0}'.format(self.max_mss)])

        # Comment
        if self.comment is None:
            self.comment = '"' + re.sub('"', '\\"', self._text) + '"'
        rule.extend(['-m', 'comment', '--comment', str(self.comment)])

        return ' '.join(rule)

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
    except Exception as ex:
        print("# firval: error: " + str(ex).replace("\n", ""))
