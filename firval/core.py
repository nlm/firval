import sys
import re
import datetime
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
    def _get_tableschains(cls):
        chains = []
        #chains.extend(cls._syschains['filter'])
        for table in cls._syschains.keys():
            for chain in cls._syschains[table]:
                chains.append('{0} {1}'.format(table, chain))
        return chains

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
                    All(int)
            },
            Optional('services'): {
                All(str, Match(cls.re['object'])): {
                    Required('proto'): All(str, In(cls.protocols)),
                    'port': Any(int,
                                Match(r'^[a-z-]+$'),
                                Match(r'^\d+(,\d+)*$')),
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
        #todo: rename vars
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
        if zone is None:
            return None
        if zone not in self.data['zones']:
            raise ConfigErro('zone not in config')
        return [elt.keys()[0] if type(elt) is dict else elt for elt in [iface for iface in self.data['zones'][zone]]]

    @staticmethod
    def _get_chainname(basechain, fromzone, tozone):
        if fromzone is None and tozone is None:
            return '{0}{1}'.format(basechain, '-default')
        return '{0}{1}{2}'.format(basechain,
                                  '-from-{0}'.format(fromzone) if fromzone is not None else '',
                                  '-to-{0}'.format(tozone) if tozone is not None else '')

    @staticmethod
    def _generate_routingrule(iif, oif, basechain, chain, from_to):
        rule = [ '-A', basechain.upper() ]
        if iif is not None:
            rule.extend(['-i', iif])
        if oif is not None:
            rule.extend(['-o', oif])

        rule.extend(['-j', '{0}'.format(chain).lower()])
        rule.extend(['-m', 'comment'])
        rule.extend(['--comment',
                     '"{0} {1}"'.format(basechain.lower(),
                                        from_to.lower())])

        return ' '.join(rule)

    def generate_rulesdata(self, data, env):

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
                chain = self._get_chainname(basechain, izone, ozone)

                # generate routing rules
                for iif in iifs or [None]:
                    for oif in oifs or [None]:

                        # Generate routing rule text
                        rulestr = self._generate_routingrule(iif, oif,
                                                             basechain,
                                                             chain, from_to)

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

                # Add rules to the rulechain
                for rule in data[table_chain][from_to]:
                    #iptrules = ['-A {0} {1}'.format(chain, iptrule) for iptrule in Rule(rule).get_iptrules()]
                    #rules[table][chain].extend(iptrules)
                    pass

        # Add rules for lo-to-lo if asked
        if 'input-from-lo' not in rules['filter']:
            rulestr = self._generate_routingrule('lo', None, 'input',
                                                 'input-from-lo',
                                                 'from lo')
            routing['filter']['input'].insert(0, rulestr)

        return { 'routing': routing, 'rules': rules }


    def __str__(self):
        """
        prints the rules represented by this object

        returns:
            string reprentation of the ruleset
        """
        data = self.data
        lne = []
        if 'rules' not in data:
            return ""

        iptdata = self.generate_rulesdata(data['rules'], {})
        from pprint import pprint
        pprint(iptdata)

        return "END"

        #######################################################################
        # Old
        #######################################################################

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
