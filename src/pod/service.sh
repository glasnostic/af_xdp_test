#!/usr/bin/env bash

ethtool -K eth0 tx off
ip link

# start iperf3 server as daemon
iperf3 -p 3091 -s -D

# start simple http server
python -m SimpleHTTPServer 80
