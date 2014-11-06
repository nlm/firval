firval
======

a netfilter firewall rules generator designed to be easy to read, write and maintain

Install
=======

    git clone https://github.com/nlm/firval
    pip install ./firval

How to use
==========

Write a yaml configuration file and feed it to firval.py,
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

    IFNAME-to-IFNAME:
      filter|nat|mangle:
        input|forward|output|...: (availability depends if in 'filter', 'nat' or 'mangle')
          - RULE
          - ...

    RULE = ((accept|reject|drop|masquerade|log)
            ((not)? from ADDRNAME ((not)? port PORTNAME)?)?
            ((not)? to ADDRNAME ((not)? port PORTNAME)?)?
            ((not)? proto (tcp|udp|icmp|any))?
            (service SERVICENAME)?
            (state (new|established|invalid))?
            (limit INTEGER/TIMEUNIT (burst INTEGER)?)?
            (comment "COMMENT")?
            (prefix "LOG_PREFIX"))
            | (jump CHAINNAME)
