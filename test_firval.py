import unittest
import firval

class Rule(unittest.TestCase):

    def setUp(self):
        self.checkset = (
            ('accept', '-j ACCEPT -m comment --comment "accept"'),
            ('reject', '-j REJECT -m comment --comment "reject"'),
            ('log prefix "te st"',
             '-j LOG --log-prefix "te st" -m comment --comment "log prefix \\"te st\\""'),
            ('nflog prefix "te st"',
             '-j NFLOG --nflog-prefix "te st" -m comment --comment "nflog prefix \\"te st\\""'),
            ('drop', '-j DROP -m comment --comment "drop"'),
            ('accept from any to any', '-j ACCEPT -m comment --comment "accept from any to any"'),
            ('accept proto tcp', '-p tcp -j ACCEPT -m comment --comment "accept proto tcp"'),
            ('accept proto udp', '-p udp -j ACCEPT -m comment --comment "accept proto udp"'),
            ('accept proto icmp', '-p icmp -j ACCEPT -m comment --comment "accept proto icmp"'),
            ('accept from any port 22 proto tcp',
             '-p tcp --sport 22 -j ACCEPT -m comment --comment "accept from any port 22 proto tcp"'),
            ('accept from port port 2000 proto udp',
             '-s port -p udp --sport 2000 -j ACCEPT -m comment --comment "accept from port port 2000 proto udp"'),
            ('accept from port port port proto tcp', 
             '-s port -p tcp --sport port -j ACCEPT -m comment --comment "accept from port port port proto tcp"'),
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
        )
        self.parseerror = (
            'omg not a rule',
            'accept proto tcp port 22',
            'accept from',
            'accept from any port',
        )
        self.configerror = (
            'accept service xyz',
            'accept from port port 22',
            'drop proto tcp type port-unreachable',
        )

    def test_match(self):
        for rule, text in self.checkset:
            print('>>> ' + rule)
            self.assertEqual(str(firval.Rule(rule)), text)

    def test_parseerror(self):
        for rule in self.parseerror:
            print('>>> ' + rule)
            self.assertRaises(firval.ParseError, firval.Rule, rule)

    def test_configerror(self):
        for rule in self.configerror:
            print('>>> ' + rule)
            self.assertRaises(firval.ConfigError, str, firval.Rule(rule))
