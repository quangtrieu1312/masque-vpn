package main

import (
    "fmt"
    "context"
    "strings"
    "net"
    "net/http"
    "net/url"
    "encoding/json"

    "github.com/quangtrieu1312/masque-vpn/server/logger"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/service"
)

func RunManagementService(ctx context.Context) {
    fd, err := net.Listen("unix", MANAGEMENT_SOCKET_PATH)
    if err != nil {
        logger.Fatal(fmt.Sprintf("cannot listen on unix socket %v: %v", MANAGEMENT_SOCKET_PATH, err))
    }
	mux := http.NewServeMux()
	mux.HandleFunc("/client", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        params, _ := url.ParseQuery(r.RequestURI)
        switch method {
        case http.MethodGet:
            break
        case http.MethodPost:
            break
        case http.MethodDelete:
            break
        default:
            w.WriteHeader(http.StatusBadRequest)
        }
    })
	mux.HandleFunc("/role", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        params, _ := url.ParseQuery(r.RequestURI)
        switch method {
        case http.MethodGet:
            break
        case http.MethodPost:
            break
        case http.MethodDelete:
            break
        default:
            w.WriteHeader(http.StatusBadRequest)
        }
    })
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        params, _ := url.ParseQuery(r.RequestURI)
        switch method {
        case http.MethodGet:
            break
        case http.MethodPost:
            break
        case http.MethodDelete:
            break
        default:
            w.WriteHeader(http.StatusBadRequest)
        }
    })
	server := http.Server{
		Handler:         mux,
	}
	go server.Serve(fd)
	defer server.Close()
    <-ctx.Done()
}
