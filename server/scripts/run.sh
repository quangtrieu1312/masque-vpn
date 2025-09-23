#!/bin/bash
function log {
    level=$(echo $1 | tr '[a-z]' '[A-Z]')
    msg=$2
    echo -e "$(date --rfc-3339 ns) bootstrap [$level]: $msg"
}

log "info" "Bootstrapping masque server"
log "info" "Environment variables ---->>\n$(printenv)"
log "info" "Creating server ca, trusted root ca (for client mTLS), and server cert"
chmod +x /scripts/*
/scripts/genServerCA.sh
/scripts/genTrustedRootCA.sh
/scripts/genServerCert.sh

log "info" "Running masque server"
chmod +x /server
/server
