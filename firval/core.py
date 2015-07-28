from __future__ import print_function, absolute_import
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
        'object': r'^[\w-]{1,255}$',
        'zone': r'^\w+$',
        'interface': r'^[\w:.]+$',
        'parameter': r'^\w+$',
        'fromto': r'^((from\s+(?P<from>\w+)\b)?\s*\b'\
                  r'(to\s+(?P<to>\w+))?|(?P<default>default)?)$',
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

    icmp_reject_types = ('icmp-net-unreachable', 'icmp-host-unreachable',
                         'icmp-port-unreachable', 'icmp-proto-unreachable',
                         'icmp-net-prohibited', 'icmp-host-prohibited')

    _syschains = {
        'filter': ('input', 'forward', 'output'),
        'nat': ('input', 'prerouting', 'output', 'postrouting'),
        'mangle': ('input', 'prerouting', 'forward', 'output', 'postrouting')
    }

    _chainsdir = {
        'from': ('input', 'prerouting', 'forward'),
        'to': ('forward', 'postrouting', 'output')
    }

    _default_parameters = {
        'auto_accept_ping': False,
        'auto_accept_established': False,
        'auto_accept_lo': False,
        'auto_drop_invalid': False,
        'auto_clamp_mss': False,
        'reject_with': 'icmp-host-prohibited',
        'log': 'log',
    }

    def __init__(self, obj):
        """
        initializes the object

        parameters:
            obj: the datastructure representing the rules
        """
        self.chains = []

        # Work (mostly) on a copy of data
        obj = dict(obj)

        # Add default to parameters
        parameters = dict(self._default_parameters)
        parameters.update(obj.get('parameters', {}))
        obj['parameters'] = parameters
        self.data = self.validate(obj)

        # Alter data if needed
        if self.data['parameters'].get('auto_accept_lo'):
            self.patch_lo(self.data)

    def patch_lo(self, data):
        if 'lo' not in data['zones']:
            data['zones']['lo'] = ['lo']
        if 'filter input' not in data['rules']:
            data['rules']['filter input'] = {}
        if 'from lo' not in data['rules']['filter input']:
            data['rules']['filter input']['from lo'] = ['accept']

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
                'auto_accept_ping': bool,
                'auto_accept_established': bool,
                'auto_accept_lo': bool,
                'auto_drop_invalid': bool,
                'auto_clamp_mss': bool,
                'reject_with': All(str, In(cls.icmp_reject_types)),
                'log': All(str, In(['log', 'nflog']))
            },
            Optional('zones'): {
                All(str, Match(cls.re['object'])): Any([
                    Any(
                        # either simple interface list
                        All(str, Match(cls.re['interface'])),
                        {All(str, Match(cls.re['interface'])):
                             Any(All(str, cls._validate_addr),
                                 [All(str, cls._validate_addr)])
                        }
                    )],
                    Any(str, Match(cls.re['interface'])),
                )
            },
            Optional('addresses'): {
                All(str, Match(cls.re['object'])):
                    All(str, cls._validate_addr)
            },
            Optional('ports'): {
                All(str, Match(cls.re['object'])):
                    Any(int, Match(Rule.re['portspec']))
            },
            Optional('services'): {
                All(str, Match(cls.re['object'])): {
                    Required('proto'): All(str, In(cls.protocols)),
                    'port': Any(int, Match(Rule.re['portspec'])),
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
            basechain = re.split(r'\s+', table_chain)[1]
            for from_to in data['rules'][table_chain]:
                dirinfos = re.match(cls.re['fromto'], from_to).groupdict()
                for elt in ('from', 'to'):
                    if (dirinfos.get(elt) and
                            basechain not in cls._chainsdir[elt]):
                        raise ConfigError('"{0}[{1}]": cannot use "{2}" in ' \
                                          'chain type "{3}"'.format(basechain,
                                                                    from_to,
                                                                    elt,
                                                                    basechain))
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
        if zone not in self.data.get('zones', {}):
            raise ConfigError('zone not in config')
        if type(self.data['zones'][zone]) == type(''):
            return [self.data['zones'][zone]]
        else:
            return [list(elt.keys())[0] if type(elt) is dict else elt \
                    for elt in [iface for iface in self.data['zones'][zone]]]

    def _get_interface_filters(self, zone, interface):
        """
        get filters for an interface in a zone
        """
        if zone is None or interface is None:
            return []

        if zone not in self.data.get('zones', {}):
            raise ConfigError('zone "{0}" not in config'.format(zone))

        if interface not in self._get_interfaces(zone):
            raise ConfigError('interface "{0}/{1}" not in config'.format(zone, interface))

        if type(self.data['zones'][zone]) == type(''):
            return []
        else:
            return [list(elt.values())[0] for elt \
                    in [iface for iface in self.data['zones'][zone]] \
                    if type(elt) is dict]

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
                                  '-from-{0}'.format(fromzone.lower()) \
                                    if fromzone is not None else '',
                                  '-to-{0}'.format(tozone.lower()) \
                                    if tozone is not None else '')

    def _generate_routingrule(self, izone, iif, ozone, oif, basechain, chain):
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
        rules = []

        baserule = ['-A', basechain.upper()]
        if iif is not None:
            baserule.extend(['-i', iif])
        if oif is not None:
            baserule.extend(['-o', oif])

        routingrule = []
        logrule = []
        actrule = []

        ifilters = self._get_interface_filters(izone, iif)
        ofilters = self._get_interface_filters(ozone, oif)

        # Routing Rule
        if len(ifilters):
            routingrule.extend(['-s', ','.join(ifilters)])
        if len(ofilters):
            routingrule.extend(['-d', ','.join(ofilters)])
        routingrule.extend(['-j', chain.lower()])
        routingrule.extend(['-m', 'comment'])
        routingrule.extend(['--comment', '"routing {0}"'.format(chain)])
        rules.append(' '.join(baserule + routingrule))

#        if len(ifilters) or len(ofilters):
#            spc=' ' if self.data['parameters']['log'] == 'log' else ''
#            actrule.extend(['-j', 'LOG'])
#            actrule.extend(['--log-prefix',
#                            Rule.logprefix.format(action='DROP',
#                                                  why='intfilter',
#                                                  chain=basechain.upper())])
#            actrule.extend(['-m', 'comment'])
#            actrule.extend(['--comment', '"log interface filter {0}"'.format(chain)])
#            rules.append(' '.join(baserule + actrule))

        if len(ifilters) or len(ofilters):
            actrule.extend(['-j', 'DROP'])
            actrule.extend(['-m', 'comment'])
            actrule.extend(['--comment', '"interface-filter {0}"'.format(chain)])
            rules.append(' '.join(baserule + actrule))

        return rules

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

        # Initialize data structs #############################################
        for table in self._syschains.keys():
            routing[table] = {}
            rules[table] = {}
            for basechain in self._syschains[table]:
                routing[table][basechain] = []

        # Table (ex: filter) and basechain (ex: input) ########################
        for table_chain in data:

            table, basechain = re.split(r'\s+', table_chain)

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
                        routingrules = self._generate_routingrule(izone, iif,
                                                                  ozone, oif,
                                                                  basechain,
                                                                  chain)

                        # Inserting Rule, most precise first, default comes last
                        if iif is None and oif is None:
                            for rulestr in routingrules:
                                routing[table][basechain].append(rulestr)
                        elif iif is None or oif is None:
                            for rulestr in routingrules:
                                routing[table][basechain].insert(
                                    len(routing[table][basechain]) - 1,
                                    rulestr)
                        else:
                            for i, rulestr in enumerate(routingrules):
                                routing[table][basechain].insert(i, rulestr)

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
                    'basechain': basechain,
                    'table': table,
                }

                # Add automatic rules
                head_rules = []
                tail_rules = []
                if env['parameters'].get('auto_drop_invalid'):
                    head_rules.append('drop state invalid')
                if env['parameters'].get('auto_accept_established'):
                    head_rules.append('accept state established')
                if env['parameters'].get('auto_accept_ping'):
                    head_rules.append('accept proto icmp type echo-request')
                if basechain in ['output', 'forward'] and env['parameters'].get('auto_clamp_mss'):
                    head_rules.append('clampmss')

                # Add rules to the rulechain
                for rule in head_rules + data[table_chain][from_to] + tail_rules:
                    iptrules = ['-A {0} {1}'.format(chain, iptrule) \
                                for iptrule in Rule(rule, env).get_iptrules()]
                    rules[table][chain].extend(iptrules)

        # Add rules for lo if asked
#        if (env['parameters'].get('auto_accept_lo') and
#            'input-from-lo' not in rules['filter']):
#            # Add routing rule
#            chain = self._build_chainname('input', 'lo', None)
#            rulestr = self._generate_routingrule('lo', 'lo', None, None,
#                                                 'input', chain)
#            routing['filter']['input'].insert(0, rulestr)
#            rules['filter']['input-from-lo'] = \
#                ['-A {0} {1}'.format(chain, iptrule) \
#                    for iptrule in Rule('accept', env).get_iptrules()]

        return {'routing': routing, 'rules': rules}

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
                env['context'] = {
                    'chain': chain,
                    'table': table,
                }
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
            'parameters': self.data.get('parameters', {}),
            'custchains': self.data.get('chains', {}),
        }

        #for interface in self._get_interfaces('mgt'):
        #    print(interface, self._get_interface_filters('mgt', interface))

        # Base Data Generation ################################################
        iptdata = self.generate_rulesdata(self.data.get('rules', {}),
                                          dict(env))

        # Custom Chains Generation ############################################
        iptdata['custchains'] = self.generate_customchains(self.data.get('chains', {}), dict(env))

        # Rules Output ########################################################
        lines.extend(self.generate_ruleslines(iptdata['rules'],
                                              iptdata['routing'],
                                              iptdata['custchains']))

        lines.append('# finished {0}'.format(datetime.now()))
        return "\n".join(lines)
