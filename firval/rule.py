import re
import voluptuous

from .exception import ConfigError, ParseError

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
        #self._aliases = aliases if aliases is not None else {}
        #self._table = table if table is not None else ''
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
            return self.env['addresses'][name]
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
            return self.env['ports'][name]
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
            return self.env['services'][name]
        except KeyError:
            return None

#    def _get_chain(self, table, name):
#        """
#        get a chain from the chains table
#
#        parameters:
#            table: the table in which the chain is
#            name: the name associated with the chain
#
#        returns:
#            the chain associated with the name
#        """
#        try:
#            return self._aliases['chains'][table][name]
#        except KeyError:
#            return None


    def __repr__(self):
        return self.__class__.__name__ + '(' + self.text + ')'

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
            rule.extend(['--sport', str(self._get_port(self.src_port))])

        # Destination port
        if not self._is_any(self.dst_port):
            if self._is_any(self.proto):
                raise ConfigError("protocol must be set when using port in '{0}'".format(self.text))
            if self.dst_port_neg is not None:
                rule.append('!')
            rule.extend(['--dport', str(self._get_port(self.dst_port))])

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
        # XXX check that
#        if self.jump_chain is not None:
#            if self._get_chain(self._table, self.jump_chain):
#                rule.extend(['-j', 'custom-{0}'.format(self.jump_chain)])
#            else:
#                raise ConfigError("unknown chain: " + self.jump_chain)

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
            self.comment = '"' + re.sub('"', '\\"', self.text) + '"'
        rule.extend(['-m', 'comment', '--comment', str(self.comment)])

        return [' '.join(rule)]
