#!/usr/bin/env bash
iptables -t nat -D POSTROUTING ! -o tun+ -j MASQUERADE
