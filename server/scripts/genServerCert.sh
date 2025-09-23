function log {
    level=$(echo $1 | tr '[a-z]' '[A-Z]')
    msg=$2
    echo -e "$(date --rfc-3339 ns) genServerCert [$level]: $msg"
}

WORK_DIR="/certs/server"

log "info" "Start"
pushd . >/dev/null
mkdir -p $WORK_DIR
cd $WORK_DIR
if [[ ! -f /data/ca/certs/ca.cert.pem ]]; then
    log "error" "No server CA found. Something must went wrong."
    exit 1
elif [[ -f $SERVER_CERT_PATH ]]; then
    log "info" "Server cert already exists. Nothing to do."
else
    log "info" "Generating server cert"
    openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
        -config /config/server-req.conf -reqexts v3_ca \
        -subj "/C=US/ST=TX/L=Dallas/O=Masque Server/CN=masque.server"
    openssl ca -in ./server.csr -out ./server.crt -config /config/ca.conf -rand_serial -batch -notext
    cat /data/ca/certs/ca.cert.pem >>./server.crt
fi
log "info" "Done"
popd >/dev/null
