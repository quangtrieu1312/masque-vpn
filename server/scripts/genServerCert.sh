#!/usr/bin/env bash
POSITIONAL_ARGS=()
FORCEUPDATE=0

C="US"
ST="TX"
L="Dallas"
O="Masque"
OU="Operations"
CN="masque.server"
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
    --dns-list)
      IFS=', ' read -r -a TMP <<< "$2"
      DNSLIST+=("${TMP[@]}")
      shift
      shift
      ;;
    --dns)
      DNSLIST+=("$2")
      shift
      shift
      ;;
    --ip-list)
      IFS=', ' read -r -a TMP <<< "$2"
      IPLIST+=("${TMP[@]}")
      shift
      shift
      ;;
    --ip)
      IPLIST+=("$2")
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
    echo -e "$(date --rfc-3339 ns) genServerCert [$level]: $msg"
}

WORK_DIR="$SERVER_CERT_DIR"

log "info" "Start"
pushd . >/dev/null
mkdir -p $WORK_DIR
cd $WORK_DIR
if [[ ! -f $SERVER_CA_DIR/certs/ca.cert.pem ]]; then
    log "error" "No server CA found. Something must went wrong."
    exit 1
elif [[ -f $SERVER_CERT_PATH ]] && [[ $FORCEUPDATE -eq 0 ]]; then
    log "info" "Server cert already exists. Nothing to do."
else
    log "info" "Generating server cert"
    tempConf=$(mktemp)
    cat /config/server-req.conf > $tempConf
    dnsListLength=${#DNSLIST[@]}
    ipListLength=${#IPLIST[@]}
    sans=""
    for (( i=0; i<${dnsListLength}; i++ )); do
        sans="${sans}DNS: ${DNSLIST[i]}"
        if [[ $i -ne $(( dnsListLength-1 )) ]] || [[ $ipListLength -ne 0 ]]; then
            sans="${sans}, "
        fi
    done
    for (( i=0; i<${ipListLength}; i++ )); do
        sans="${sans}IP: ${IPLIST[i]}"
        if [[ $i -ne $(( ipListLength-1 )) ]]; then
            sans="${sans}, "
        fi
    done
    if [[ dnsListLength -ne 0 ]] || [[ ipListLength -ne 0 ]]; then
        sans="subjectAltName = ${sans}"
        printf '%s\n' "$sans" >> $tempConf
    fi
    openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
        -config $tempConf -reqexts v3_ca \
        -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN"
    openssl ca -in ./server.csr -out ./server.crt -config /config/server-ca.conf -rand_serial -batch -notext
    cat $SERVER_CA_DIR/certs/ca.cert.pem >>./server.crt
fi
log "info" "Done"
popd >/dev/null
