#!/usr/bin/env bash

function curl_test() {
  local target=$1
  echo "curl test to $target"
  curl  --noproxy $target --connect-timeout 10 -m 60 -v $target
}

function iperf_test() {
  local target=$1
  echo "iperf test to $target"
  iperf3 -p 3091 -c $target -M 1450 -n 30M
}

function ping_test() {
  local target=$1
  echo "ping test to $target"
  ping -c 10 $target
}

ethtool -K eth0 tx off
ip link
ip neigh replace $ROUTER lladdr $ROUTER_MAC dev eth0
ip neigh replace $CLIENT lladdr $CLIENT_MAC dev eth0

sleep 30s

# curl test
curl_test $SERVER
curl_test $ROUTER

# ping test
ping_test $SERVER
ping_test $ROUTER

# iperf test
iperf_test $SERVER
iperf_test $ROUTER
