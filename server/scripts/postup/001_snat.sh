#!/usr/bin/env bash
iptables -t nat -I POSTROUTING 1 ! -o tun+ -j MASQUERADE
