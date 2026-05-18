package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -target bpf -I/usr/include" MasqueXDP xdp.c
