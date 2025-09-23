function log {
    level=$(echo $1 | tr '[a-z]' '[A-Z]')
    msg=$2
    echo -e "$(date --rfc-3339 ns) genServerCert [$level]: $msg"
}

clientName=$1
if [[ -z "$clientName" ]]; then
    log "error" "Must pass client name as the only parameter"
    exit 1
fi

WORK_DIR="/certs/client"

pushd . >/dev/null
mkdir -p $WORK_DIR
cd $WORK_DIR
if [[ ! -f /data/trustedca/certs/ca.cert.pem ]]; then
    log "error" "No trusted root CA found. Something must went wrong."
    exit 1
else
    log "info" "Generating client cert"
    randId=$(dd if=/dev/urandom bs=1k count=1 2>/dev/null | base64 | tr -dc 'a-zA-Z0-9' | cut -c1-64)
    mkdir -p $clientName
    openssl req -new -newkey rsa:2048 -nodes -keyout $clientName/client.key -out $clientName/client.csr \
        -config /config/client-req.conf -extensions v3_ca \
        -subj "/C=US/ST=TX/L=Dallas/O=Masque Client/CN=$randId"
    openssl ca -in $clientName/client.csr -out $clientName/client.crt -config /config/trustedca.conf -rand_serial -batch -notext
    cat /data/trustedca/certs/ca.cert.pem >>$clientName/client.crt
    log "info" "New cert id $randId has been created"
fi
log "info" "Done"
popd >/dev/null
