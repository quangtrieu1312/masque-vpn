function log {
    level=$(echo $1 | tr '[a-z]' '[A-Z]')
    msg=$2
    echo -e "$(date --rfc-3339 ns) genTrustedRootCA [$level]: $msg"
}

WORK_DIR="/data/trustedca"

log "info" "Checking server CA"
pushd . >/dev/null
mkdir -p $WORK_DIR
cd $WORK_DIR
if [[ ! -f $WORK_DIR/private/ca.key.pem ]]; then
    log "info" "No server CA found. Creating one."
    mkdir -p ./private ./certs ./crl ./newcerts
    touch ./index.txt ./serial
    openssl genrsa -out private/ca.key.pem 4096
    openssl req -config /config/ca-req.conf -key private/ca.key.pem -new -x509 \
        -sha256 -extensions v3_ca -out certs/ca.cert.pem \
        -subj "/C=US/ST=CA/L=San Jose/O=Masque Client Root CA/CN=client.masque.root" \
        -days 3650
fi
log "info" "Done"
popd >/dev/null
