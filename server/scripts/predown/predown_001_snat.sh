#!/usr/bin/env bash
iptables -t nat -D POSTROUTING -o eth+ -j MASQUERADE
