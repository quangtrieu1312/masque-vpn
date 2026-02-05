package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
    "net/url"

	"github.com/quangtrieu1312/masque-vpn/server/constants"
	"github.com/quangtrieu1312/masque-vpn/server/logger"
	"github.com/quangtrieu1312/masque-vpn/server/domain"
	"github.com/quangtrieu1312/masque-vpn/server/service"
)


type DeleteClientsRequest struct {
    IDs []int64 `json:"ids"`
}

type UpsertClientsRequest struct {
    Names []string `json:"names"`
}

type AssignRolesToClientsRequest struct {
    ClientIDs []int64 `json:"client_ids"`
    RoleIDs []int64 `json:"role_ids"`
}

type UnassignRolesToClientsRequest struct {
    ClientIDs []int64 `json:"client_ids"`
    RoleIDs []int64 `json:"role_ids"`
}

type UpdateClientNameRequest struct {
    Name string `json:"name"`
}

type DeleteRolesRequest struct {
    IDs []int64 `json:"ids"`
}

type UpsertRolesRequest struct {
    Names []string `json:"names"`
}

type AssignResourcesToRolesRequest struct {
    ResourceIDs []int64 `json:"resource_ids"`
    RoleIDs []int64 `json:"role_ids"`
}

type UnassignResourcesToRolesRequest struct {
    ResourceIDs []int64 `json:"resource_ids"`
    RoleIDs []int64 `json:"role_ids"`
}

type FetchClientResourcesRequest struct {
    ClientID int64 `json:"client_id"`
}

type UpdateRoleNameRequest struct {
    Name string `json:"name"`
}

type DeleteResourcesRequest struct {
    IDs []int64 `json:"ids"`
}

type UpsertResourcesRequest struct {
    Resources []domain.Resource `json:"names"`
}

type UpdateResourceNameRequest struct {
    Name string `json:"name"`
}

type ResetDHCPRequest struct {
    FirstIP int64 `json:"fist_ip"`
    LastIP int64 `json:"last_ip"`
}
func RunManagementService(ctx context.Context) {
    fd, err := net.Listen("unix", constants.MANAGEMENT_SOCKET_PATH)
    if err != nil {
        logger.Fatal(fmt.Sprintf("Cannot listen on unix socket %v: %v", constants.MANAGEMENT_SOCKET_PATH, err))
    }
	mux := http.NewServeMux()
	mux.HandleFunc("/client/{id}", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
        if err != nil {
            logger.Trace(fmt.Sprintf("Invalid client id: %v", err))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        switch method {
        case http.MethodGet:
            data, err := service.GetClientByID(ctx, id)
            if err != nil {
                logger.Debug(fmt.Sprintf("GET /client/%v error: %v", id, err))
                w.WriteHeader(http.StatusBadRequest)
            } else {
                jsonBytes, err := json.Marshal(*data)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Cannot marshal client data to json"))
                    w.WriteHeader(http.StatusInternalServerError)
                } else {
                    w.Write(jsonBytes)
                }
            }
            break
        case http.MethodPost:
            var body UpdateClientNameRequest
            err := json.NewDecoder(r.Body).Decode(&body)
            if err != nil {
                logger.Debug(fmt.Sprintf("Invalid POST /client/%v: %v", id, err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            ok, err := service.UpdateClientName(ctx, id, body.Name)
            if ok {
                w.WriteHeader(http.StatusOK)
            } else {
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
	mux.HandleFunc("/client", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        params, err := url.ParseQuery(r.URL.RawQuery)
        if err != nil {
            logger.Fatal(fmt.Sprintf("Cannot parse request param for GET /client: %v", err))
            return
        }
        switch method {
        case http.MethodGet:
            data, err := service.GetAllClients(ctx)
            if err != nil {
                logger.Debug(fmt.Sprintf("GET /client error: %v", err))
                w.WriteHeader(http.StatusBadRequest)
            } else {
                jsonBytes, err := json.Marshal(*data)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Cannot marshal client data to json: %v", err))
                    w.WriteHeader(http.StatusInternalServerError)
                } else {
                    w.Write(jsonBytes)
                }
            }
            break
        case http.MethodPost:
            requestType := params.Get("type")
            switch requestType {
            case "upsert":
                var body UpsertClientsRequest
                err := json.NewDecoder(r.Body).Decode(&body)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Invalid POST /client: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                    return
                }
                clientIDs, _ := service.UpsertClients(ctx, body.Names)
                if err == nil {
                    w.WriteHeader(http.StatusOK)
                    jsonBytes, err := json.Marshal(*clientIDs)
                    if err != nil {
                        logger.Debug(fmt.Sprintf("Cannot marshal clientIDs to json: %v", err))
                        w.WriteHeader(http.StatusInternalServerError)
                    } else {
                        w.Write(jsonBytes)
                    }
                } else {
                    w.WriteHeader(http.StatusBadRequest)
                }
                break
            case "assign":
                var body AssignRolesToClientsRequest
                err := json.NewDecoder(r.Body).Decode(&body)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Invalid POST /client: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                    return
                }
                ok, _ := service.AssignRolesToClients(ctx, body.RoleIDs, body.ClientIDs)
                if ok {
                    w.WriteHeader(http.StatusOK)
                } else {
                    w.WriteHeader(http.StatusBadRequest)
                }
                break
            case "unassign":
                var body UnassignRolesToClientsRequest
                err := json.NewDecoder(r.Body).Decode(&body)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Invalid POST /client: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                    return
                }
                ok, _ := service.AssignRolesToClients(ctx, body.RoleIDs, body.ClientIDs)
                if ok {
                    w.WriteHeader(http.StatusOK)
                } else {
                    w.WriteHeader(http.StatusBadRequest)
                }
                break
            default:
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        case http.MethodDelete:
            var body DeleteClientsRequest
            err := json.NewDecoder(r.Body).Decode(&body)
            if err != nil {
                logger.Debug(fmt.Sprintf("Invalid DELETE /client: %v", err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            ok, err := service.DeleteClients(ctx,body.IDs)
            if ok {
                w.WriteHeader(http.StatusOK)
            } else {
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
	mux.HandleFunc("/role/{id}", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
        if err != nil {
            logger.Trace(fmt.Sprintf("Invalid role id: %v", err))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        switch method {
        case http.MethodGet:
            data, err := service.GetRoleByID(ctx, id)
            if err != nil {
                logger.Debug(fmt.Sprintf("GET /role/%v error: %v", id, err))
                w.WriteHeader(http.StatusBadRequest)
            } else {
                jsonBytes, err := json.Marshal(*data)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Cannot marshal role data to json: %v", err))
                    w.WriteHeader(http.StatusInternalServerError)
                } else {
                    w.Write(jsonBytes)
                }
            }
            break
        case http.MethodPost:
            var body UpdateRoleNameRequest
            err := json.NewDecoder(r.Body).Decode(&body)
            if err != nil {
                logger.Debug(fmt.Sprintf("Invalid POST /role/%v: %v", id, err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            ok, _ := service.UpdateRoleName(ctx, id, body.Name)
            if ok {
                w.WriteHeader(http.StatusOK)
            } else {
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
	mux.HandleFunc("/role", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        params, err := url.ParseQuery(r.URL.RawQuery)
        if err != nil {
            logger.Fatal(fmt.Sprintf("Cannot parse request param for GET /role: %v", err))
            return
        }
        switch method {
        case http.MethodGet:
            data, err := service.GetAllRoles(ctx)
            if err != nil {
                logger.Debug(fmt.Sprintf("GET /role error: %v", err))
                w.WriteHeader(http.StatusBadRequest)
            } else {
                jsonBytes, err := json.Marshal(*data)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Cannot marshal role data to json: %v", err))
                    w.WriteHeader(http.StatusInternalServerError)
                } else {
                    w.Write(jsonBytes)
                }
            }
            break
        case http.MethodPost:
            requestType := params.Get("type")
            switch requestType {
            case "upsert":
                var body UpsertRolesRequest
                err := json.NewDecoder(r.Body).Decode(&body)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Invalid POST /role: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                    return
                }
                ok, _ := service.UpsertRoles(ctx, body.Names)
                if ok {
                    w.WriteHeader(http.StatusOK)
                } else {
                    w.WriteHeader(http.StatusBadRequest)
                }
                break
            case "assign":
                var body AssignResourcesToRolesRequest
                err := json.NewDecoder(r.Body).Decode(&body)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Invalid POST /role: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                    return
                }
                ok, _ := service.AssignResourcesToRoles(ctx, body.ResourceIDs, body.RoleIDs)
                if ok {
                    w.WriteHeader(http.StatusOK)
                } else {
                    w.WriteHeader(http.StatusBadRequest)
                }
                break
            case "unassign":
                var body UnassignResourcesToRolesRequest
                err := json.NewDecoder(r.Body).Decode(&body)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Invalid POST /role: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                    return
                }
                ok, _ := service.UnassignResourcesToRoles(ctx, body.ResourceIDs, body.RoleIDs)
                if ok {
                    w.WriteHeader(http.StatusOK)
                } else {
                    w.WriteHeader(http.StatusBadRequest)
                }
                break
            default:
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        case http.MethodDelete:
            var body DeleteRolesRequest
            err := json.NewDecoder(r.Body).Decode(&body)
            if err != nil {
                logger.Debug(fmt.Sprintf("Invalid DELETE /role: %v", err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            ok, _ := service.DeleteRoles(ctx,body.IDs)
            if ok {
                w.WriteHeader(http.StatusOK)
            } else {
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
	mux.HandleFunc("/resource/{id}", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
        if err != nil {
            logger.Trace(fmt.Sprintf("Invalid resource id: %v", err))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        switch method {
        case http.MethodGet:
            data, err := service.GetResourceByID(ctx, id)
            if err != nil {
                logger.Debug(fmt.Sprintf("GET /resource/%v error: %v", id, err))
                w.WriteHeader(http.StatusBadRequest)
            } else {
                jsonBytes, err := json.Marshal(*data)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Cannot marshal resource data to json: %v", err))
                    w.WriteHeader(http.StatusInternalServerError)
                } else {
                    w.Write(jsonBytes)
                }
            }
            break
        case http.MethodPost:
            var body UpdateResourceNameRequest
            err := json.NewDecoder(r.Body).Decode(&body)
            if err != nil {
                logger.Debug(fmt.Sprintf("Invalid POST /client/%v: %v", id, err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            ok, _ := service.UpdateResourceName(ctx, id, body.Name)
            if ok {
                w.WriteHeader(http.StatusOK)
            } else {
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        params, err := url.ParseQuery(r.URL.RawQuery)
        if err != nil {
            logger.Fatal(fmt.Sprintf("Cannot parse request param for GET /client: %v", err))
            return
        }
        switch method {
        case http.MethodGet:
            data, err := service.GetAllResources(ctx)
            if err != nil {
                logger.Debug(fmt.Sprintf("GET /resource error: %v", err))
                w.WriteHeader(http.StatusBadRequest)
            } else {
                jsonBytes, err := json.Marshal(*data)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Cannot marshal resource data to json: %v", err))
                    w.WriteHeader(http.StatusInternalServerError)
                } else {
                    w.Write(jsonBytes)
                }
            }
            break
        case http.MethodPost:
            requestType := params.Get("type")
            switch requestType {
            case "upsert":
                var body UpsertResourcesRequest
                err := json.NewDecoder(r.Body).Decode(&body)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Invalid POST /resource: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                    return
                }
                ok, _ := service.UpsertResources(ctx, &body.Resources)
                if ok {
                    w.WriteHeader(http.StatusOK)
                } else {
                    w.WriteHeader(http.StatusBadRequest)
                }
                break
            case "client":
                var body FetchClientResourcesRequest
                err := json.NewDecoder(r.Body).Decode(&body)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Invalid POST /resource: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                    return
                }
                data, err := service.GetClientResources(ctx, body.ClientID)
                if err != nil {
                    logger.Debug(fmt.Sprintf("POST /resource error: %v", err))
                    w.WriteHeader(http.StatusBadRequest)
                } else {
                    jsonBytes, err := json.Marshal(*data)
                    if err != nil {
                        logger.Debug(fmt.Sprintf("Cannot marshal resource data to json: %v", err))
                        w.WriteHeader(http.StatusInternalServerError)
                    } else {
                        w.Write(jsonBytes)
                    }
                }
                break
            default:
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        case http.MethodDelete:
            var body DeleteResourcesRequest
            err := json.NewDecoder(r.Body).Decode(&body)
            if err != nil {
                logger.Debug(fmt.Sprintf("Invalid DELETE /resource: %v", err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            ok, _ := service.DeleteResources(ctx,body.IDs)
            if ok {
                w.WriteHeader(http.StatusOK)
            } else {
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
	mux.HandleFunc("/dhcp", func(w http.ResponseWriter, r *http.Request) {
        method := r.Method
        switch method {
        case http.MethodGet:
            data, err := service.GetAllAvailableIPRanges(ctx)
            if err != nil {
                logger.Debug(fmt.Sprintf("GET /dhcp error: %v", err))
                w.WriteHeader(http.StatusBadRequest)
            } else {
                jsonBytes, err := json.Marshal(*data)
                if err != nil {
                    logger.Debug(fmt.Sprintf("Cannot marshal dhcp data to json: %v", err))
                    w.WriteHeader(http.StatusInternalServerError)
                } else {
                    w.Write(jsonBytes)
                }
            }
            break
        case http.MethodPut:
            var body ResetDHCPRequest
            err := json.NewDecoder(r.Body).Decode(&body)
            if err != nil {
                logger.Debug(fmt.Sprintf("Invalid POST /dhcp: %v", err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            ok, _ := service.ResetDHCP(ctx, body.FirstIP, body.LastIP)
            if ok {
                w.WriteHeader(http.StatusOK)
            } else {
                w.WriteHeader(http.StatusBadRequest)
            }
            break
        default:
            w.WriteHeader(http.StatusMethodNotAllowed)
        }
    })
	server := http.Server{
		Handler:         mux,
	}
	go server.Serve(fd)
	defer server.Close()
    <-ctx.Done()
}
