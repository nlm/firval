import sys
import re
from datetime import datetime
from voluptuous import Schema, Required, Optional, Any, All, Invalid, Match, In
from voluptuous import MultipleInvalid
from netaddr import IPNetwork
import yaml
import argparse

from .exception import ConfigError, ParseError
from .rule import Rule

class Firval(object):
    """
    The main Firval class
    """
    re = {
        'object': r'^\w{1,128}$',
        'zone': r'^\w+$',
        'interface': r'^[\w:.]+$',
        'parameter': r'^\w+$',
        'fromto': r'^((from\s+(?P<from>\w+)\b)?\s*\b(to\s+(?P<to>\w+))?|(?P<default>default)?)$',
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

    _chainsdir = {
        'from': ('input', 'prerouting', 'forward'),
        'to': ('forward', 'postrouting', 'output')
    }

    _logprefix = 'firval: ACT={action} IZ={in_zone} OZ={out_zone}'


    def __init__(self, obj):
        """
        initializes the object

        parameters:
            obj: the datastructure representing the rules
        """
        self.chains = []
        self.data = self.validate(obj)


    @classmethod
    def _get_tableschains(cls):
        """
        builds a list of possible tables chains

        parameters:
            cls: the class

        returns:
            a list of tables base chains
        """
        chains = []
        for table in cls._syschains.keys():
            for chain in cls._syschains[table]:
                chains.append('{0} {1}'.format(table, chain))
        return chains


    @staticmethod
    def _validate_addr(address):
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
            Optional('parameters'): {
                All(str, Match(cls.re['parameter'])): Any(str, [str], bool, int)
            },
            Optional('zones'): {
                All(str, Match(cls.re['object'])): [
                    Any(
                        # either simple interface
                        All(str, Match(cls.re['interface'])),
                        { All(str, Match(cls.re['interface'])):
                            Any(All(str, cls._validate_addr),
                                [ All(str, cls._validate_addr) ])
                        }
                    )
                ]
            },
            Optional('addresses'): {
                All(str, Match(cls.re['object'])):
                    All(str, cls._validate_addr)
            },
            Optional('ports'): {
                All(str, Match(cls.re['object'])):
                    Any(int, Match(r'^\d+(,\d+)*$'))
            },
            Optional('services'): {
                All(str, Match(cls.re['object'])): {
                    Required('proto'): All(str, In(cls.protocols)),
                    'port': Any(int, Match(r'^\d+(,\d+)*$')),
                    'type': All(str, In(cls.icmp_types)),
                }
            },
            Optional('chains'): {
                All(str, In(cls._syschains.keys())): {
                    All(str, Match(cls.re['object'])):
                        [All(str, Match(Rule.pattern))]
                }
            },
            Required('rules'): {
                All(str, Any(In(cls._get_tableschains()))): {
                    All(str, Any(Match(cls.re['fromto']))): [
                        All(str, Match(Rule.pattern)),
                    ],
                }
            }
        })(data)

        # Check constraints like 'input chains don't have output interface'
        for table_chain in data['rules'].keys():
            basechain = re.split('\s+', table_chain)[1]
            for from_to in data['rules'][table_chain]:
                dirinfos = re.match(cls.re['fromto'], from_to).groupdict()
                for elt in ('from', 'to'):
                    if dirinfos.get(elt) and basechain not in cls._chainsdir[elt]:
                        raise ConfigError('"{0}[{1}]": cannot use "{2}" in chain type "{3}"'.format(basechain,
                                                                                                    from_to,
                                                                                                    elt,
                                                                                                    basechain))
        print('# schema validation ok')
        return data

    def _get_interfaces(self, zone):
        """
        get interfaces list for a zone

        parameters:
            zone: a zone name

        returns:
            a list of interface names
        """
        if zone is None:
            return None
        if zone not in self.data['zones']:
            raise ConfigError('zone not in config')
        return [elt.keys()[0] if type(elt) is dict else elt for elt in [iface for iface in self.data['zones'][zone]]]

    def _get_interface_filters(self, zone, interface):
        """
        get filters for an interface in a zone
        """
        if zone is None or interface is None:
            return None

        if zone not in self.data['zones']:
            raise ConfigError('zone "{0}" not in config'.format(zone))

        if interface not in self._get_interfaces(zone):
            raise ConfigError('interface "{0}/{1}" not in config'.format(zone, interface))

        return [elt.values()[0] if type(elt) is dict else None for elt in [iface for iface in self.data['zones'][zone]]]

    @staticmethod
    def _build_chainname(basechain, fromzone, tozone):
        """
        builds a chain name according to format

        parameters:
            basechain: the base chain name (input, formward, output...)
            fromzone: source zone name
            tozone: destination zone name

        returns:
            the chain name
        """
        if fromzone is None and tozone is None:
            return '{0}{1}'.format(basechain.lower(), '-default')
        return '{0}{1}{2}'.format(basechain.lower(),
                                  '-from-{0}'.format(fromzone.lower()) if fromzone is not None else '',
                                  '-to-{0}'.format(tozone.lower()) if tozone is not None else '')

    @classmethod
    def _generate_routingrule(cls, izone, iif, ozone, oif, basechain, chain):
        """
        generates a routing rule according to specs

        parameters:
            izone: source zone name
            iif: source interface name
            ozone: destination zone name
            oif: destination interface name
            basechain: the base chain name (input, forward, output...)
            chain: the target chain name

        returns:
            an iptables chain jump rule
        """
        rule = [ '-A', basechain.upper() ]
        if iif is not None:
            rule.extend(['-i', iif])
        if oif is not None:
            rule.extend(['-o', oif])

        rule.extend(['-j', '{0}'.format(chain).lower()])
        rule.extend(['-m', 'comment'])
        rule.extend(['--comment',
                     '"routing {0}"'.format(cls._build_chainname(basechain,
                                                                 izone, ozone))])

        return ' '.join(rule)


    def generate_rulesdata(self, data, env):
        """
        generate a structure containing rules data
        it converts the yaml structure into another data structure,
        in which some data is converted and some other automatically added

        parameters:
            data: the rules part of the data structure from yaml
            env: a dict containing some other parts of the base structure
        """

        rules = {}
        routing = {}
        custchains = {}

        # Table (ex: filter) and basechain (ex: input) ########################
        for table_chain in data:

            print(table_chain)
            table, basechain = re.split('\s+', table_chain)

            # initialize routing table
            if table not in routing:
                routing[table] = {}
            if basechain not in routing[table]:
                routing[table][basechain] = []

            # initialize rules table
            if table not in rules:
                rules[table] = {}

            print('# {} {}'.format(table, basechain))

            # From and To informations ########################################
            for from_to in data[table_chain]:

                # get info needed for generation
                fromto_infos = re.match(self.re['fromto'], from_to).groupdict()
                izone = fromto_infos.get('from')
                ozone = fromto_infos.get('to')
                iifs = self._get_interfaces(izone)
                oifs = self._get_interfaces(ozone)
                chain = self._build_chainname(basechain, izone, ozone)

                # generate routing rules
                for iif in iifs or [None]:
                    for oif in oifs or [None]:

                        # Generate routing rule text
                        rulestr = self._generate_routingrule(izone, iif,
                                                             ozone, oif,
                                                             basechain,
                                                             chain)

                        # Inserting Rule, most precise first, default comes last
                        if iif is None and oif is None:
                            routing[table][basechain].append(rulestr)
                        elif iif is None or oif is None:
                            routing[table][basechain].insert(
                                len(routing[table][basechain]) - 1, rulestr)
                        else:
                            routing[table][basechain].insert(0, rulestr)

                # Create rulechain in the rules table
                if chain not in rules[table]:
                    rules[table][chain] = []

                # Customize environment
                env['basechain'] = basechain
                env['context'] = {
                    'izone': izone,
                    'ozone': ozone,
                    'iifs': iifs,
                    'oifs': oifs,
                    'chain': chain,
                    'basechain': basechain
                }

                # Add automatic rules
                # XXX: add conditions
                head_rules = []
                tail_rules = []
                if True:
                    head_rules.append('accept state established')
                if True:
                    head_rules.append('accept proto icmp type echo-request')
                if basechain in ['output', 'forward'] and True:
                    head_rules.append('clampmss')

                # Add rules to the rulechain
                for rule in head_rules + data[table_chain][from_to] + tail_rules:
                    iptrules = ['-A {0} {1}'.format(chain, iptrule) for iptrule in Rule(rule, env).get_iptrules()]
                    rules[table][chain].extend(iptrules)

        # Add rules for lo-to-lo if asked
        # XXX add condition
        if 'input-from-lo' not in rules['filter']:
            # Add routing rule
            rulestr = self._generate_routingrule('lo', 'lo',
                                                 None, None,
                                                 'input',
                                                 'input-from-lo')
            routing['filter']['input'].insert(0, rulestr)
            # Add rule
            chain = self._build_chainname('input', 'lo', None)
            rules['filter']['input-from-lo'] = ['-A {0} {1}'.format(chain, iptrule) for iptrule in Rule('accept', env).get_iptrules()]

        return { 'routing': routing, 'rules': rules }


    @staticmethod
    def generate_customchains(data, env):
        """
        generates rules for custom chains
        """
        custchains = {}
        for table in data:
            custchains[table] = {}
            for chain in data[table]:
                custchains[table][chain] = []
                for rule in data[table][chain]:
                    iptrules = ['-A {0} {1}'.format(chain, iptrule) for iptrule in Rule(rule, env).get_iptrules()]
                    custchains[table][chain].extend(iptrules)
        return custchains


    @classmethod
    def generate_ruleslines(cls, rules, routing, custchains):
        lns = []

        # Tables ###############################################################
        for table in rules:
            if len(lns) > 1:
                lns.append("COMMIT")
            lns.append("*{0}".format(table))

            # system chains
            for chain in cls._syschains[table]:
                lns.append(':{0} ACCEPT [0:0]'.format(chain.upper()))

            # custom routing chains
            for chain in sorted(rules[table].keys()):
                lns.append(':{0} - [0:0]'.format(chain))

            # custom chains
            if table in custchains:
                for chain in sorted(custchains[table].keys()):
                    lns.append(':custom-{0} - [0:0]'.format(chain.lower()))

            # routing rules
            for chain in sorted(routing[table].keys()):
                for rule in routing[table][chain]:
                    lns.append(rule)

            # chain rules
            for chain in sorted(rules[table].keys()):
                for rule in rules[table][chain]:
                    lns.append(rule)

            # custom chain rules
            if table in custchains:
                for chain in custchains[table]:
                    for rule in custchains[table][chain]:
                        lns.append(rule)

        lns.append('COMMIT')
        return lns


    def __str__(self):
        """
        prints the rules represented by this object

        returns:
            string reprentation of the ruleset
        """

        lines = ['# generated by firval {0}'.format(datetime.now())]

        env = {
            'addresses': self.data.get('addresses', {}),
            'ports': self.data.get('ports', {}),
            'services': self.data.get('services', {}),
        }

        #for interface in self._get_interfaces('mgt'):
        #    print(interface, self._get_interface_filters('mgt', interface))

        # Base Data Generation #################################################
        iptdata = self.generate_rulesdata(self.data.get('rules', {}), dict(env))

        # Custom Chains Generation #############################################
        iptdata['custchains'] = self.generate_customchains(self.data.get('chains', {}), dict(env))

        from pprint import pprint
        pprint(iptdata)


        # Rules Output #########################################################
        lines.extend(self.generate_ruleslines(iptdata['rules'],
                                              iptdata['routing'],
                                              iptdata['custchains']))

        lines.append('# finished {0}'.format(datetime.now()))
        return "\n".join(lines)

