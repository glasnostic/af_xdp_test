#!/bin/bash

ethtool -K eth0 tx off
iptables-legacy -t filter -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP

/go/bin/router
