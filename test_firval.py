import unittest
from firval.core import Firval
from firval.rule import Rule
from firval.exception import ParseError, ConfigError
from voluptuous import MultipleInvalid
from netaddr import AddrFormatError


class FirvalSimpleTest(unittest.TestCase):

    def setUp(self):
        self.firval = Firval({ 'rules': {} })

    def test_invalid_data(self):
        self.assertRaises(MultipleInvalid, Firval, {})

    def test_simple(self):
        output = str(self.firval)
        self.assertEqual(20, len(output.split("\n")))

    def test_gettablechains(self):
        self.assertEqual(len(self.firval._get_tableschains()), 12)


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


class FirvalTest(unittest.TestCase):

    def setUp(self):
        self.firval = Firval({ 'rules': {} })


#class RuleTest(unittest.TestCase):
#
#    def setUp(self):
#
#        self.env = {
#            'parameters': {
#                'log': 'nflog',
#            },
#            'services': {
#            },
#        }
#
#        self.checkset = (
#            ('accept','-j ACCEPT -m comment --comment "accept"'),
#            ('drop', '-j DROP -m comment --comment "drop"'),
#            ('masquerade', '-j MASQUERADE -m comment --comment "masquerade"'),
#            ('reject', '-j REJECT --reject-with icmp-host-prohibited -m comment --comment "reject"'),
#            ('clampmss', '-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu -m comment --comment "clampmss"'),
#            ('log prefix ""', '-j LOG --log-prefix "" -m comment --comment "log prefix \\"\\""'),
#            ('log prefix "te st"', '-j LOG --log-prefix "te st" -m comment --comment "log prefix \\"te st\\""'),
#            ('drop', '-j DROP -m comment --comment "drop"'),
#            ('accept from any to any', '-j ACCEPT -m comment --comment "accept from any to any"'),
#            ('accept proto tcp', '-p tcp -j ACCEPT -m comment --comment "accept proto tcp"'),
#            ('accept proto udp', '-p udp -j ACCEPT -m comment --comment "accept proto udp"'),
#            ('accept proto icmp', '-p icmp -j ACCEPT -m comment --comment "accept proto icmp"'),
#
#            ('accept from any port 22 proto tcp',
#             '-p tcp --sport 22 -j ACCEPT -m comment --comment "accept from any port 22 proto tcp"'),
#            ('accept from port port 2000 proto udp',
#             '-s port -p udp --sport 2000 -j ACCEPT -m comment --comment "accept from port port 2000 proto udp"'),
#            ('accept from port port port proto tcp',
#             '-s port -p tcp --sport port -j ACCEPT -m comment --comment "accept from port port port proto tcp"'),
#            ('accept from 1.2.3.4', '-s 1.2.3.4 -j ACCEPT -m comment --comment "accept from 1.2.3.4"'),
#            ('accept not from 1.2.3.4', '! -s 1.2.3.4 -j ACCEPT -m comment --comment "accept not from 1.2.3.4"'),
#            ('accept to 1.2.3.4', '-d 1.2.3.4 -j ACCEPT -m comment --comment "accept to 1.2.3.4"'),
#            ('accept not to 1.2.3.4', '! -d 1.2.3.4 -j ACCEPT -m comment --comment "accept not to 1.2.3.4"'),
#            ('drop proto icmp type port-unreachable',
#             '-p icmp --icmp-type port-unreachable -j DROP -m comment --comment "drop proto icmp type port-unreachable"'),
#            ('accept state established',
#             '-m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "accept state established"'),
#            ('drop proto icmp type an-unknown-icmp-type',
#             '-p icmp --icmp-type an-unknown-icmp-type -j DROP -m comment --comment "drop proto icmp type an-unknown-icmp-type"'),
#            ('accept limit 1/s burst 5',
#             '-m limit --limit 1/s --limit-burst 5 -j ACCEPT -m comment --comment "accept limit 1/s burst 5"'),
#            ('drop state invalid', '-m state --state INVALID -j DROP -m comment --comment "drop state invalid"'),
#        )
#        self.parseerror = (
#            'omg not a rule',
#            'accept proto tcp port 22',
#            'accept from',
#            'accept from any port',
#            'clampmss from port 22',
#            'accept limit 1/sec burst 5',
#        )
#        self.configerror = (
#            'accept service xyz',
#            'accept from port port 22',
#            'drop proto tcp type port-unreachable',
#        )
#
#    def test_match_simple(self):
#        print()
#        for rule, text in self.checkset:
#            print('>>> ' + rule)
#            result = Rule(rule, self.env).get_iptrules()
#            self.assertEqual(result[0], text)
#
#    def test_parseerror(self):
#        print()
#        for rule in self.parseerror:
#            print('>>> ' + rule)
#            self.assertRaises(ParseError, Rule, rule, {})
#
#    def test_configerror(self):
#        for rule in self.configerror:
#            print('>>> ' + rule)
#            self.assertRaises(ConfigError, str, Rule(rule, {}))
#
