package main

import (
    "context"
	"bufio"
	"log"
	"flag"
    "strings"
	"os"
)

func ParseConfig(ctx context.Context) {
    var configPath string
    flag.StringVar(&configPath, "f", "/opt/masqued/masqued.conf", "Path to config file")
    file, err := os.Open(configPath)
    if err != nil {
        log.Fatalf("Failed to open config file %v: %v", configPath, err)
        os.Exit(1)
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        data := strings.Trim(scanner.Text(), " \t")
        if len(data) == 0 {
            continue
        }
        isKey := true
        k := ""
        v := ""
        for pos, char := range data {
            if (pos == 0 && char == '#') {
                continue
            }
            if (isKey && char == '=') {
                isKey = false
                continue
            }
            if (isKey) {
                k+=string(char)
            } else {
                v+=string(char)
            }
        }
        if (k == "") {
            log.Fatalf("Invalid config format")
        }
        ctx = context.WithValue(ctx, k, v)
    }
}
