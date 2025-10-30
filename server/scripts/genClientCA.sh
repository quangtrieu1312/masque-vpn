#!/usr/bin/env bash
POSITIONAL_ARGS=()
FORCEUPDATE=0
C="US"
ST="CA"
L="San Jose"
O="Maque Client Root CA"
OU="R&D"
CN="client.masque.root"

while [[ $# -gt 0 ]]; do
  case $1 in
    -f|--force)
      FORCEUPDATE=1
      shift # past argument
      ;;
    --country)
      C=$2
      shift
      shift
      ;;
    --state)
      ST=$2
      shift
      shift
      ;;
    --locality)
      L=$2
      shift
      shift
      ;;
    --organization)
      O=$2
      shift
      shift
      ;;
    --organization-unit)
      OU=$2
      shift
      shift
      ;;
    --common-name)
      CN=$2
      shift
      shift
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
    echo -e "$(date --rfc-3339 ns) genTrustedRootCA [$level]: $msg"
}

WORK_DIR="$CLIENT_CA_DIR"

log "info" "Checking client CA"
pushd . >/dev/null
mkdir -p $WORK_DIR
cd $WORK_DIR
if [[ ! -f $WORK_DIR/private/ca.key.pem ]] || [[ $FORCEUPDATE -eq 1 ]]; then
    log "info" "Creating CA."
    rm -rf ./*
    mkdir -p ./private ./certs ./crl ./newcerts
    touch ./index.txt ./serial
    openssl genrsa -out private/ca.key.pem 4096
    openssl req -config /config/ca-req.conf -key private/ca.key.pem -new -x509 \
        -sha256 -extensions v3_ca -out certs/ca.cert.pem \
        -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN" \
        -days 3650
fi
log "info" "Done"
popd >/dev/null
