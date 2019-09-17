#!/usr/bin/env bash

ethtool -K eth0 tx off
ip link
ip neigh replace $ROUTER lladdr $ROUTER_MAC dev eth0
ip neigh replace $CLIENT lladdr $CLIENT_MAC dev eth0

# start iperf3 server as daemon
iperf3 -p 3091 -s -D

# start simple http server
python -m SimpleHTTPServer 80
