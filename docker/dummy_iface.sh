#!/bin/sh

ip link add dummy1 type dummy
ip addr add 198.51.100.210/24 dev dummy1
ip link set dummy1 up