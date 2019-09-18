#!/usr/bin/env bash

BASEDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source $BASEDIR/message.sh

function curl_test() {
  local target=$1
  message "curl test to $target"
  curl  --noproxy $target --connect-timeout 10 -m 60 -v $target
}

function iperf_test() {
  local target=$1
  message "iperf test to $target"
  iperf3 -p 3091 -c $target -M 1450 -n 30M
}

function ping_test() {
  local target=$1
  message "ping test to $target"
  ping -c 16 $target
}

ethtool -K eth0 tx off
ip link
message "setup static ARP tables for test"
ip neigh replace $ROUTER lladdr $ROUTER_MAC dev eth0
ip neigh replace $CLIENT lladdr $CLIENT_MAC dev eth0

message "sleep 30s for waiting other test containers ready"
sleep 30s

# ping test
ping_test $SERVER
ping_test $ROUTER

# curl test
curl_test $SERVER
curl_test $ROUTER

# iperf test
iperf_test $SERVER
iperf_test $ROUTER
