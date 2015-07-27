from __future__ import print_function, absolute_import

import re
import voluptuous

from .exception import ConfigError, ParseError

class Rule(object):
    """
    Object representing an iptables rule
    """

    pattern = r'^\s*(' + \
        r'(jump\s+(?P<jump_chain>\S+))|' + \
        r'(?P<clampmss>clampmss)|' + \
        r'(?P<setmss>setmss\s+(?P<max_mss>\d+))|' + \
        r'(?P<log>log_)?(?P<action>accept|reject|drop|masquerade|log)' + \
        r'(?:(?:\s+(?P<src_neg>not))?\s+from\s+(?P<src_addr>\S+(,\S+)*)' + \
        r'(?:(?:\s+(?P<src_port_neg>not))?\s+port\s+(?P<src_port>\S+(,\S+)*))?)?' + \
        r'(?:(?:\s+(?P<dst_neg>not))?\s+to\s+(?P<dst_addr>\S+(,\S+)*)' + \
        r'(?:(?:\s+(?P<dst_port_neg>not))?\s+port\s+(?P<dst_port>\S+(,\S+)*))?)?' + \
        r'(?:(?:\s+(?P<proto_neg>not))?\s+proto\s+(?P<proto>tcp|udp|icmp|any))?' + \
        r'(?:(?:\s+(?P<icmp_type_neg>not))?\s+type\s+(?P<icmp_type>\S+))?' + \
        r'(?:\s+service\s+(?P<service>\w+(,\w+)*))?' + \
        r'(?:\s+state\s+(?P<state>new|established|invalid))?' + \
        r'(?:\s+limit\s+(?P<limit>\d+/(s(econd)*|m(inute)*|h(our)*|d(ay)*))' + \
        r'(?:\s+burst\s+(?P<limit_burst>\S+))?)?' + \
        r'(?:\s+prefix\s+(?P<log_prefix>"[^"]*"))?' + \
        r')\s*$'

    re = {
        'portspec': r'^\d+(-\d+)?(,\d+(-\d+)?)*$',
        'ipspec': r'^\d+(\.\d+){3}(,\d+(\.\d+){3})*$',
    }

    def __init__(self, text, env):
        """
        initializes the Rule object

        parameters:
            text: the rule written with firval simplified syntax
            env: address, ports, services and chains dictionnary
        """
        self.comment = None
        self.data = None
        self.text = text
        self.env = env
        self.modules = []
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
        parse text and return an attribute dict
        if it matches a rule pattern

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

    def _get_address(self, address):
        """
        get an address from the address table

        parameters:
            name: the name associated with the address

        returns:
            the address associated with the name
        """
        try:
            addrs = []
            for addr in [self.env['addresses'][name] for name in address.split(',')]:
                addrs.append(addr)
            return ','.join(addrs)
        except KeyError:
            if re.match(r'^\d+(\.\d+){3}(,\d+(\.\d+){3})*$', address):
                return address
            raise ConfigError("address '{0}' not found".format(address))

    def _get_port(self, value):
        """
        get a portspec from the port table

        parameters:
            value: the name associated with the port
                   or a portspec (ex: 22,80-90)

        returns:
            a portspec
        """
        return ','.join([str(self._get_portnum(port)) for port in value.split(',')])

    def _get_portnum(self, value):
        """
        get a port number from the port table
        """
        try:
            return self.env['ports'][value]
        except KeyError:
            if re.match(r'^\d+$', value):
                return value
            raise ConfigError("port '{0}' not found".format(value))

    @classmethod
    def portspec_to_mp(cls, portspec):
        if not re.match(cls.re['portspec'], portspec):
            raise ParseError('{0} is not valid portspec'.format(portspec))
        portlist = []
        for ranges in portspec.split(','):
            ports = sorted([int(x) for x in ranges.split('-')])
            portlist.append(':'.join([str(x) for x in ports]))
        return ','.join([str(x) for x in portlist])
        #return ','.join([str(x) for x in sorted(set(portlist),
        #                                        lambda x, y: cmp(int(x), int(y)))])


    def _get_service(self, service):
        """
        get a service from the service table

        parameters:
            service: the name associated with the service

        returns:
            the service associated with the name
        """
        try:
            proto = None
            types = []
            ports = []
            for service in [self.env['services'][name] for name in service.split(',')]:
                if proto is None:
                    proto = service['proto']
                elif proto != service['proto']:
                    raise ConfigError('Service {0} with proto {1} mixed with proto {2}'.format(name, service['proto'], proto))
                if proto == 'icmp':
                    types.append(service['type'])
                else:
                    ports.append(service['port'])
            if proto == 'icmp':
                return {'proto': proto, 'type': ','.join(types)}
            else:
                return {'proto': proto, 'port': ','.join([str(port) for port in ports])}
        except KeyError:
            raise ConfigError('service not found')

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
            return self.env['custchains'][table][name]
        except KeyError:
            return None

    def __repr__(self):
        return self.__class__.__name__ + '(' + self.text + ')'

    def include_module(self, modulename):
        if modulename not in self.modules:
            self.modules.append(modulename)
            return ['-m', modulename]
        return []

    def make_logrule(self, action):
        ctx = self.env.get('context', {})
        rule = []
        rule.extend(['-j', self.env['parameters']['log']])
        rule.append('--{0}-prefix'.format(self.env['parameters']['log']))
        rule.append('"firval: ACT={action} CHN={chain}{spc}"'
                    .format(action=action.upper(),
                            spc=' ' if self.env['parameters']['log'] == 'log' else '',
                            **self.env.get('context', {})))

        rule.extend(self.include_module('comment'))
        rule.extend(['--comment', '"log"'])
        return ' '.join(rule)

    def get_iptrules(self):
        """
        process the content of this rule

        returns:
            a table of iptables rule strings
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
                raise ConfigError("protocol must be set when using port in '{0}'".format(self.text))
            if self.src_port_neg is not None:
                rule.append('!')
            portspec = self._get_port(self.src_port)
            if re.match(r'^\d+$', portspec):
                rule.extend(['--sport', str(portspec)])
            else:
                rule.extend(self.include_module('multiport'))
                rule.extend(['--sports', self.portspec_to_mp(portspec)])

        # Destination port
        if not self._is_any(self.dst_port):
            if self._is_any(self.proto):
                raise ConfigError("protocol must be set when using port in '{0}'".format(self.text))
            if self.dst_port_neg is not None:
                rule.append('!')
            portspec = self._get_port(self.dst_port)
            if re.match(r'^\d+$', portspec):
                rule.extend(['--dport', str(portspec)])
            else:
                rule.extend(self.include_module('multiport'))
                rule.extend(['--dports', self.portspec_to_mp(portspec)])

        # ICMP Type
        if not self._is_any(self.icmp_type):
            if self._is_any(self.proto):
                raise ConfigError("protocol must be set when using icmp-type in '{0}'".format(self.text))
            if self.proto != 'icmp':
                raise ConfigError("protocol must be 'icmp' when using icmp-type in '{0}'".format(self.text))
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
                portspec = service['port']
                if re.match(r'^\d+$', portspec):
                    rule.extend(['--dport', str(portspec)])
                else:
                    rule.extend(self.include_module('multiport'))
                    rule.extend(['--dports', self.portspec_to_mp(portspec)])

        # State
        if not self._is_any(self.state):
            rule.extend(self.include_module('state'))
            if self.state == 'new':
                rule.extend(['--state', 'NEW'])
            elif self.state == 'established':
                rule.extend(['--state', 'ESTABLISHED,RELATED'])
            elif self.state == 'invalid':
                rule.extend(['--state', 'INVALID'])

        # Limit
        if self.limit is not None:
            rule.extend(self.include_module('limit'))
            rule.extend(['--limit', str(self.limit)])
            if not self._is_any(self.limit_burst):
                rule.extend(['--limit-burst', str(self.limit_burst)])

        # Actions
        if self.action == 'log':
            rule.extend(['-j', str(self.env['parameters']['log'])])
        elif self.action is not None:
            rule.extend(['-j', str(self.action.upper())])

        # Actions parameters
        if self.action == 'reject':
            rule.extend(['--reject-with', 'icmp-host-prohibited'])
        elif self.action == 'log':
            if self.log_prefix is not None:
                rule.extend(['--{0}-prefix'.format(self.env['parameters']['log']),
                             str(self.log_prefix)])
            else:
                raise ConfigError("log prefix requires 'log' or 'nflog' action")

        # Jump to custom chain
        if self.jump_chain is not None:
            if self._get_chain(self.env['context']['table'], self.jump_chain):
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
        self.comment = '"' + re.sub('"', '\\"', self.text) + '"'
        rule.extend(self.include_module('comment'))
        rule.extend(['--comment', str(self.comment)])

        logrules = []
        if self.log is not None:
            logrules.append(self.make_logrule(self.action))

        return logrules + [' '.join(rule)]
