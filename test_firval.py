import unittest
from firval.core import Firval
from firval.rule import Rule
from firval.exception import ParseError, ConfigError
from voluptuous import MultipleInvalid
from netaddr import AddrFormatError


class FirvalCoreSimpleTests(unittest.TestCase):

    def setUp(self):
        self.firval = Firval({ 'rules': {} })

    def test_invalid_data(self):
        self.assertRaises(MultipleInvalid, Firval, {})

    def test_simple(self):
        output = str(self.firval)
        self.assertEqual(20, len(output.split("\n")))

    def test_gettablechains(self):
        self.assertEqual(len(self.firval._get_tableschains()), 12)

    def test_structs(self):
        self.assertTrue(len(self.firval.icmp_types) > 0)
        self.assertTrue(len(self.firval.protocols) > 0)
        self.assertTrue(len(self.firval.icmp_reject_types) > 0)

    def test_validateipaddr(self):
        addresses = (
            '192.168.10.20',
            '192.168.10.0/23',
            '1.1.1.1',
            '255.255.255.255',
        )
        for addr in addresses:
            self.firval._validate_addr(addr)

        self.assertRaises(AddrFormatError, self.firval._validate_addr, '192.168.290.2')
        self.assertRaises(AddrFormatError, self.firval._validate_addr, 'test')
        self.assertRaises(AddrFormatError, self.firval._validate_addr, '192.168..2')
        self.assertRaises(AddrFormatError, self.firval._validate_addr, '1120.168.290.2')

    def test_buildchainname(self):
        dataset = (
            (('input', 'exmpl', 'tst'), 'input-from-exmpl-to-tst'),
            (('output', None, 'tst'), 'output-to-tst'),
            (('forward', 'trial', None), 'forward-from-trial'),
            (('forward', None, None), 'forward-default'),
            (('input', None, None), 'input-default'),
        )

        for data in dataset:
            self.assertEqual(self.firval._build_chainname(*data[0]), data[1])

    def test_generateroutingrule(self):
        dataset = (
            (('izn', 'eth0', 'ozn', 'eth1', 'input', 'input-from-izn-to-ozn'),
             '-A INPUT -i eth0 -o eth1 -j input-from-izn-to-ozn ' \
             '-m comment --comment "routing input-from-izn-to-ozn"'),
            (('zone0', 'eth2', 'zone1', 'eth4', 'forward', 'forward-from-zone0-to-zone1'),
             '-A FORWARD -i eth2 -o eth4 -j forward-from-zone0-to-zone1 ' \
             '-m comment --comment "routing forward-from-zone0-to-zone1"'),
            ((None, None, 'zone1', 'eth1', 'forward', 'forward-to-zone1'),
             '-A FORWARD -o eth1 -j forward-to-zone1 ' \
             '-m comment --comment "routing forward-to-zone1"'),
            (('zone0', 'eth0', None, None, 'input', 'input-from-zone0'),
             '-A INPUT -i eth0 -j input-from-zone0 ' \
             '-m comment --comment "routing input-from-zone0"'),
        )

        for data in dataset:
            self.assertEqual(self.firval._generate_routingrule(*data[0]), data[1])

    def test_validate(self):
        dataset = (
        )
        self.firval.validate({ 'rules': {} })

    def test_validate_invalid(self):
        dataset = (
            {'rules': []},
            {'bla': 'ok'},
        )
        for data in dataset:
            self.assertRaises(MultipleInvalid, self.firval.validate, data)

    def test_validate_configerror(self):
        dataset = (
            {'rules': {'filter input': {'to zone0': []}}},
            {'rules': {'nat input': {'to zone0': []}}},
            {'rules': {'filter output': {'from zone1': []}}},
        )
        for data in dataset:
            self.assertRaises(ConfigError, self.firval.validate, data)

    def test_validate_syschains(self):
        dataset = (
            {'rules': {'filter forward': {}}},
            {'rules': {'nat prerouting': {}}},
            {'rules': {'nat postrouting': {}}},
        )
        for data in dataset:
            self.firval.validate(data)

        dataset = (
            {'rules': {'randomthing': {}}},
            {'rules': {'nat forward': {}}},
            {'rules': {'multi forward': {}}},
        )
        for data in dataset:
            self.assertRaises(MultipleInvalid, self.firval.validate, data)


class FirvalCoreTests(unittest.TestCase):

    def setUp(self):
        self.zones = {
            'zone0': ['eth0', 'eth1'],
            'zone1': ['eth2', {'eth3': '127.0.0.1'}],
            'zone2': [{'eth4': ['127.0.0.2', '127.0.0.3']}],
        }

        self.rules = {
            'filter forward': {
                'from zone0': [
                    'accept'
                ]
            }
        }


    def test_get_interfaces(self):
        firval = Firval({'rules': {}, 'zones': self.zones})
        self.assertEqual(firval._get_interfaces(None), None)
        self.assertRaises(ConfigError, firval._get_interfaces, 'nonexistent')
        self.assertEqual(firval._get_interfaces('zone0'), ['eth0', 'eth1'])
        self.assertEqual(firval._get_interfaces('zone1'), ['eth2', 'eth3'])
        self.assertEqual(firval._get_interfaces('zone2'), ['eth4'])

    def test_get_interface_filters(self):
        firval = Firval({'rules': {}, 'zones': self.zones})
        self.assertEqual(firval._get_interface_filters(None, 'x'), None)
        self.assertEqual(firval._get_interface_filters('x', None), None)
        self.assertRaises(ConfigError, firval._get_interface_filters,
                          'nonexistent', 'eth0')
        self.assertRaises(ConfigError, firval._get_interface_filters,
                          'zone0', 'nonexistent')
        self.assertRaises(ConfigError, firval._get_interface_filters,
                          'zone0', 'eth3')
        self.assertEqual(firval._get_interface_filters('zone0', 'eth0'), [])
        self.assertEqual(firval._get_interface_filters('zone1', 'eth3'), ['127.0.0.1'])

    def test_generate_rulesdata(self):
        firval = Firval({'rules': self.rules, 'zones': self.zones})
        self.assertEqual(len(str(firval)), 669)

class RuleTest(unittest.TestCase):

    def setUp(self):

        self.env = {
            'addresses': {
                'addr0': '127.0.1.8',
                'port': '127.0.0.9',
            },
            'ports': {
                'port0': 1234,
                'port1': '5678',
                'port2': '2233,4455',
                'port': 9999,
            },
            'parameters': {
                'log': 'nflog',
            },
            'services': {
            },
        }

        self.checkset = (
            ('accept','-j ACCEPT -m comment --comment "accept"'),
            ('drop', '-j DROP -m comment --comment "drop"'),
            ('masquerade', '-j MASQUERADE -m comment --comment "masquerade"'),
            ('reject', '-j REJECT --reject-with icmp-host-prohibited ' \
                       '-m comment --comment "reject"'),
            ('clampmss', '-p tcp --tcp-flags SYN,RST SYN -j TCPMSS ' \
                         '--clamp-mss-to-pmtu -m comment --comment "clampmss"'),
            ('log prefix ""', '-j NFLOG --nflog-prefix "" ' \
                              '-m comment --comment "log prefix \\"\\""'),
            ('log prefix "te st"', '-j NFLOG --nflog-prefix "te st" ' \
                                   '-m comment --comment "log prefix \\"te st\\""'),
            ('drop', '-j DROP -m comment --comment "drop"'),
            ('accept from any to any', '-j ACCEPT -m comment --comment "accept from any to any"'),
            ('accept proto tcp', '-p tcp -j ACCEPT -m comment --comment "accept proto tcp"'),
            ('accept proto udp', '-p udp -j ACCEPT -m comment --comment "accept proto udp"'),
            ('accept proto icmp', '-p icmp -j ACCEPT -m comment --comment "accept proto icmp"'),
            ('accept from any port 22 proto tcp',
             '-p tcp --sport 22 -j ACCEPT -m comment --comment "accept from any port 22 proto tcp"'),
            ('accept from port port 2000 proto udp',
             '-s 127.0.0.9 -p udp --sport 2000 -j ACCEPT -m comment --comment "accept from port port 2000 proto udp"'),
            ('accept from port port port proto tcp',
             '-s 127.0.0.9 -p tcp --sport 9999 -j ACCEPT -m comment --comment "accept from port port port proto tcp"'),
            ('accept from 1.2.3.4', '-s 1.2.3.4 -j ACCEPT -m comment --comment "accept from 1.2.3.4"'),
            ('accept not from 1.2.3.4', '! -s 1.2.3.4 -j ACCEPT -m comment --comment "accept not from 1.2.3.4"'),
            ('accept to 1.2.3.4', '-d 1.2.3.4 -j ACCEPT -m comment --comment "accept to 1.2.3.4"'),
            ('accept not to 1.2.3.4', '! -d 1.2.3.4 -j ACCEPT -m comment --comment "accept not to 1.2.3.4"'),
            ('drop proto icmp type port-unreachable',
             '-p icmp --icmp-type port-unreachable -j DROP -m comment --comment "drop proto icmp type port-unreachable"'),
            ('accept state established',
             '-m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "accept state established"'),
            ('drop proto icmp type an-unknown-icmp-type',
             '-p icmp --icmp-type an-unknown-icmp-type -j DROP -m comment --comment "drop proto icmp type an-unknown-icmp-type"'),
            ('accept limit 1/s burst 5',
             '-m limit --limit 1/s --limit-burst 5 -j ACCEPT -m comment --comment "accept limit 1/s burst 5"'),
            ('drop state invalid', '-m state --state INVALID -j DROP -m comment --comment "drop state invalid"'),
        )

        self.parseerror = (
            'omg not a rule',
            'accept proto tcp port 22',
            'accept from',
            'accept from any port',
            'clampmss from port 22',
            'accept limit 1/sec burst 5',
        )

        self.configerror = (
            'accept service xyz',
            'accept from port port 22',
            'drop proto tcp type port-unreachable',
        )

    def test_attr(self):
        rule = Rule('accept', self.env)
        self.assertEqual(rule.nonexistent, None)
        self.assertEqual(rule.action, 'accept')

    def test_address(self):
        rule = Rule('accept', self.env)
        self.assertEqual(rule._get_address('addr0'), '127.0.1.8')
        self.assertRaises(ConfigError, rule._get_address, 'nonexistent')

    def test_getportnum(self):
        rule = Rule('accept', self.env)
        self.assertEqual(rule._get_portnum('port0'), '1234')
        self.assertEqual(rule._get_portnum('port1'), '5678')
        self.assertEqual(rule._get_portnum('port2'), '2233,4455')
        self.assertRaises(ConfigError, rule._get_portnum, 'nonexistent')

    def test_portspec(self):
        rule = Rule('accept', self.env)
        testset = (
            ('22', '22'),
            ('32,22', '32,22'),
            ('11,8000-9000,55', '11,8000:9000,55'),
            ('11,9000-8000,9-10,55-22,3', '11,8000:9000,9:10,22:55,3'),
        )
        for elt in testset:
            self.assertEqual(rule.portspec_to_mp(elt[0]), elt[1])

    def test_match_simple(self):
        print()
        for rule, text in self.checkset:
            print('>>> ' + rule)
            result = Rule(rule, self.env).get_iptrules()
            self.assertEqual(result[0], text)

    def test_parseerror(self):
        print()
        for rule in self.parseerror:
            print('>>> ' + rule)
            self.assertRaises(ParseError, Rule, rule, self.env)

    def test_configerror(self):
        print()
        for rule in self.configerror:
            print('>>> ' + rule)
            self.assertRaises(ConfigError, Rule(rule, self.env).get_iptrules)

