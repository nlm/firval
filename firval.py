#!/usr/bin/env python

import re
import datetime
from voluptuous import Schema,Required,All,Invalid,Match,In
from netaddr import IPNetwork

class ParseError(Exception):
    pass


class Firval():
    _re = {
        'obj': '^[a-zA-Z0-9-]{1,32}$',
        'zone': '^[a-z0-9]+$',
        'if': '^[a-z0-9:]+$',
        'ruleset': '^[a-z0-9]+-to-[a-z0-9]+$',
    }

    _protos = ['tcp', 'udp', 'icmp']

    _icmptypes = [ 'echo-reply', 'pong', 'destination-unreachable',
    'network-unreachable', 'host-unreachable', 'protocol-unreachable',
    'port-unreachable', 'fragmentation-needed', 'source-route-failed',
    'network-unknown', 'host-unknown', 'network-prohibited',
    'host-prohibited', 'TOS-network-unreachable',
    'TOS-host-unreachable', 'communication-prohibited',
    'host-precedence-violation', 'precedence-cutoff', 'source-quench',
    'redirect', 'network-redirect', 'host-redirect',
    'TOS-network-redirect', 'TOS-host-redirect', 'echo-request',
    'ping', 'router-advertisement', 'router-solicitation',
    'time-exceeded', 'ttl-exceeded', 'ttl-zero-during-transit',
    'ttl-zero-during-reassembly', 'parameter-problem', 'ip-header-bad',
    'required-option-missing', 'timestamp-request', 'timestamp-reply',
    'address-mask-request', 'address-mask-reply' ]

    _syschains = {
        'filter': [ 'input', 'forward', 'output' ],
        'nat': [ 'prerouting', 'input', 'output', 'postrouting' ],
        'mangle': [ 'prerouting', 'input', 'forward', 'output', 'postrouting' ]
    }

    def __init__(self, obj, strict=None):
        self.chains = []
        self.data = self._validate(obj)

    def _get_iface(self, name):
        try:
            return self.data['interfaces'][name]
        except KeyError:
            return None

    def _valid_addr(self, address):
        ip = IPNetwork(address)

    def _validate(self, data):
        Schema({
            Required('interfaces'): {
                All(str, Match(self._re['obj'])):
                    All(str, Match(self._re['if']))
            },
            'addresses': {
                All(str, Match(self._re['obj'])):
                    All(str, self._valid_addr)
            },
            'ports': {
                All(str, Match(self._re['obj'])):
                    All(int)
            },
            'services': {
                All(str, Match(self._re['obj'])): {
                    Required('proto'): All(str, In(self._protos)),
                    'port': int,
                    'type': All(str, In(self._icmptypes)),
                }
            },
            'rulesets': {
                All(str, Match(self._re['ruleset'])): {
                    'filter': {
                        All(str, In(self._syschains['filter'])):
                            [ All(str, Match(_Rule.pattern)) ],
                    },
                    'nat': {
                        All(str, In(self._syschains['nat'])):
                            [ All(str, Match(_Rule.pattern)) ],
                    },
                    'mangle': {
                        All(str, In(self._syschains['mangle'])):
                            [ All(str, Match(_Rule.pattern)) ],
                    }
                }
            }
        })(data)
        return data

    def __str__(self):
        data = self.data
        ln = []
        if 'rulesets' not in data:
            return ""

        rules = {}
        routing = {}

        # Rulesets Generation #################################################
        for ruleset in data['rulesets']:

            # Interfaces  #####################################################
            (izone, ozone) = re.match('^(\S+)-to-(\S+)$', ruleset).groups()
            assert izone, ozone

            if izone == 'any':
                iif = None
            else:
                iif = self._get_iface(izone)
                if iif is None:
                    raise ParseError("{} interface is not defined".format(izone))

            if ozone == 'any':
                oif = None
            else:
                oif = self._get_iface(ozone)
                if oif is None:
                    raise ParseError("{} interface is not defined".format(ozone))

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

                    rule.extend(['-j', '{}-{}'.format(ruleset, chain).lower()])
                    rule.extend(['-m', 'comment'])
                    rule.extend(['--comment', '"{} {} -> {}"'.format(chain, izone, ozone)])

                    r = ' '.join(rule)

                    # default rule comes last
                    if iif is None and oif is None:
                        routing[table][chain].append(r)
                    elif iif is None or oif is None:
                        routing[table][chain].insert(len(routing[table][chain]) - 1, r)
                    else:
                        routing[table][chain].insert(0, r)

                    # Rules ###################################################
                    if chain not in rules[table]:
                        rules[table][chain] = {}

                    rules[table][chain][ruleset] = []

                    for rule in data['rulesets'][ruleset][table][chain]:
                        rules[table][chain][ruleset].append('-A {}-{} {}'.format(ruleset, chain.lower(), str(_Rule(rule, aliases=self.data))))

        # Rules Output ########################################################

        ln = ['# generated by firval {}'.format(datetime.datetime.now())]

        # Tables ##############################################################
        for table in rules:
            ln.append("*{}".format(table))

            # system chains
            for chain in self._syschains[table]:
                ln.append(':{} ACCEPT [0:0]'.format(chain.upper()))

            # custom routing chains
            for chain in rules[table]:
                for ruleset in rules[table][chain]:
                    ln.append(':{}-{} - [0:0]'.format(ruleset, chain.lower()))

            # routing rules
            for chain in routing[table]:
                for rule in routing[table][chain]:
                    ln.append(rule)

            # chain rules
            for chain in rules[table]:
                for ruleset in rules[table][chain]:
                    for rule in rules[table][chain][ruleset]:
                        ln.append(rule)

        ln.append('COMMIT')
        ln.append('# finished {}'.format(datetime.datetime.now()))
        return "\n".join(ln)


class _Rule():
    pattern = '^\s*' + \
        '(?P<action>accept|reject|drop|masquerade|log)' + \
        '(?:(?:\s+(?P<src_neg>not))?\s+from\s+(?P<src_addr>\S+)' + \
        '(?:(?:\s+(?P<src_port_neg>not))?\s+port\s+(?P<src_port>\S+))?)?' + \
        '(?:(?:\s+(?P<dst_neg>not))?\s+to\s+(?P<dst_addr>\S+)' + \
        '(?:(?:\s+(?P<dst_port_neg>not))?\s+port\s+(?P<dst_port>\S+))?)?' + \
        '(?:(?:\s+(?P<proto_neg>not))?\s+proto\s+(?P<proto>tcp|udp|icmp|any))?' + \
        '(?:\s+service\s+(?P<service>\S+))?' + \
        '(?:\s+state\s+(?P<state>new|established))?' + \
        '(?:\s+limit\s+(?P<limit>\d+/\S)(?:\s+burst\s+(?P<limit_burst>\S+)))?' + \
        '(?:\s+comment\s+(?P<comment>"[^"]+"))?' + \
        '(?:\s+prefix\s+(?P<log_prefix>"[^"]+"))?' + \
        '\s*$'

    def __init__(self, text, aliases=None):
        self._text = text
        self._aliases = aliases if aliases is not None else {}
        self._parse(text)

    def __getattr__(self, name):
        if self.data is not None and name in self.data:
            return self.data[name]
        return None

    def _parse(self, text):
        result = re.match(self.pattern, text)
        if result:
            self.data = result.groupdict()
        else:
            raise ParseError(text)

    def _is_any(self, value):
        return value is None or value == 'any'

    def _get_address(self, name):
        try:
            return self._aliases['addresses'][name]
        except KeyError:
            return name

    def _get_port(self, name):
        try:
            return self._aliases['ports'][name]
        except KeyError:
            return name

    def _get_service(self, name):
        try:
            return self._aliases['services'][name]
        except KeyError:
            return None

    def __repr__(self):
        return self.__class__.__name__ + '(' + self._text + ')'

    def __str__(self):
        r = []        

        # Source address
        if not self._is_any(self.src_addr):
            if self.src_neg is not None:
                r.append('!')
            r.extend(['-s', str(self._get_address(self.src_addr))])

        # Destination address
        if not self._is_any(self.dst_addr):
            if self.dst_neg is not None:
                r.append('!')
            r.extend(['-d', str(self._get_address(self.dst_addr))])

        # Protocol
        if not self._is_any(self.proto):
            if self.proto_neg is not None:
                r.append('!')
            r.extend(['-p', str(self.proto)])

        # Source port
        if not self._is_any(self.src_port):
            if self._is_any(self.proto):
                raise ParseError("protocol must be set when using port in '{}'".format(self._text))
            if self.src_port_neg is not None:
                r.append('!')
            r.extend(['--sport', str(self._get_port(self.src_port))])

        # Destination port
        if not self._is_any(self.dst_port):
            if self._is_any(self.proto):
                raise ParseError("protocol must be set when using port in '{}'".format(self._text))
            if self.dst_port_neg is not None:
                r.append('!')
            r.extend(['--dport', str(self._get_port(self.dst_port))])

        # Service
        if self.service is not None:
            if not self._is_any(self.dst_port) or not self._is_any(self.proto):
                raise ParseError('service conflicts with dport or proto:', self.service)
            service = self._get_service(self.service)
            if service is None:
                raise ParseError('unknown service: ' + self.service)
            r.extend(['-p', service['proto']])
            if service['proto'] in ['tcp', 'udp']:
                r.extend(['--dport', str(service['port'])])

        # State
        if not self._is_any(self.state):
            if self.state == 'new':
                r.extend(['-m', 'state', '--state', 'NEW'])
            elif self.state == 'established':
                r.extend(['-m', 'state', '--state', 'ESTABLISHED,RELATED'])

        # Limit
        if self.limit is not None:
            r.extend(['-m', 'limit', '--limit', str(self.limit)])
            if not self._is_any(self.limit_burst):
                r.extend(['--limit-burst', str(self.limit_burst)])

        # Actions
        if self.action is not None:
            r.extend(['-j', str(self.action.upper())])

        # Prefix
        if self.log_prefix is not None:
            if self.action == 'log':
                r.extend(['--log-prefix', str(self.log_prefix)])
            else:
                raise ParseError("log prefix requires 'log' action")
        elif self.action == 'log':
            r.extend(['--log-prefix', 'AUTO-PREFIX'])

        # Comment
        if self.comment is None:
            self.comment = '"' + re.sub('"', '\\"', self._text) + '"'
        r.extend(['-m', 'comment', '--comment', str(self.comment)])

        return ' '.join(r)

if __name__ == '__main__':
    import sys
    import yaml
    print str(Firval(yaml.load(sys.stdin)))
