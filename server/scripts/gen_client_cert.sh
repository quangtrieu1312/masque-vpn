#!/usr/bin/env bash
source /opt/masqued/scripts/helper.sh

POSITIONAL_ARGS=()
FORCEUPDATE=0

while [[ $# -gt 0 ]]; do
  case $1 in
    -f|--force)
      FORCEUPDATE=1
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters
function log {
    level=$(echo $1 | tr '[a-z]' '[A-Z]')
    msg=$2
    echo -e "$(date --rfc-3339 ns) genClientCert [$level]: $msg"
}

id=$1
if [[ -z "$id" ]]; then
    log "error" "usage: $0 [id] [name]"
    exit 1
fi
clientName=$2
if [[ -z "$clientName" ]]; then
    log "error" "usage: $0 [id] [name]"
    exit 1
fi

WORK_DIR=$CLIENT_CERT_DIR

pushd . >/dev/null
mkdir -p $WORK_DIR
cd $WORK_DIR
if [[ ! -f $CLIENT_CA_DIR/certs/ca.cert.pem ]]; then
    log "error" "No trusted root CA found. Something must went wrong."
    exit 1
else
    log "info" "Generating client cert"
    mkdir -p "$id"
    openssl req -new -newkey rsa:2048 -nodes -keyout $id/client.key -out $id/client.csr \
        -config /opt/masqued/extras/peer-req.conf -extensions v3_ca \
        -subj "/C=US/ST=TX/L=Dallas/O=Masque Client/CN=$clientName"
    openssl ca -in $id/client.csr -out $id/client.crt -config /opt/masqued/extras/peer-ca.conf -rand_serial -batch -notext
    cat $CLIENT_CA_DIR/certs/ca.cert.pem >>$id/client.crt
    ln -s $SERVER_CA_DIR/certs/ca.cert.pem $id/ca.crt
    zip $id/bundle.zip $id/*.crt $id/*.key
    rm -rf $id/*.crt $id/*.key
    log "info" "New cert for client='$clientName', id='$id' has been created. Bundle available at $WORK_DIR/$clientName."
fi
log "info" "Done"
popd >/dev/null
