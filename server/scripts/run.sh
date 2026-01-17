#!/usr/bin/env bash
source /opt/masqued/scripts/helper.sh
source /opt/masqued/config/daemon.conf
function log {
    level=$(echo $1 | tr '[a-z]' '[A-Z]')
    msg=$2
    echo -e "$(date --rfc-3339 ns) bootstrap [$level]: $msg"
}

log "info" "Initializing masque server"
log "info" "Environment variables ---->>\n$(printenv)"
log "info" "Creating server CA, server cert, and client CA"

chmod +x $SCRIPT_DIR/*



echo 'alias genServerCA='"'"'bash -c '$SCRIPT_DIR'/gen_server_CA.sh'"'" >>/root/.bashrc
echo 'alias genServerCert='"'"'bash -c '$SCRIPT_DIR'/gen_server_cert.sh'"'" >>/root/.bashrc
echo 'alias genClientCA='"'"'bash -c '$SCRIPT_DIR'/gen_client_CA.sh'"'" >>/root/.bashrc
echo 'alias genClientCert='"'"'bash -c '$SCRIPT_DIR'/gen_client_cert.sh'"'" >>/root/.bashrc

$SCRIPT_DIR/gen_server_CA.sh
$SCRIPT_DIR/gen_server_cert.sh -f --dns-list ${SAN_DNS_LIST} --ip-list ${SAN_IP_LIST}
$SCRIPT_DIR/gen_client_CA.sh

log "info" "Running masque daemon"
chmod +x $BASE/masqued
ln -s $BASE/masqued /usr/sbin/masqued
masqued
