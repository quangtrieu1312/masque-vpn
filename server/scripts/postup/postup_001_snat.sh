#!/usr/bin/env bash
iptables -t nat -A POSTROUTING -o eth+ -j MASQUERADE
