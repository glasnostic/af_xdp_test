#!/bin/bash

ethtool -K eth0 tx off

/go/bin/router
