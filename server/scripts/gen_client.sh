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
    echo -e "$(date --rfc-3339 ns) genClient [$level]: $msg"
}

clientName=$1
if [[ -z "$clientName" ]]; then
    log "error" "Must pass client name as the only parameter"
    exit 1
fi

id=$(curl --unix-socket $MANAGEMENT_SOCKET_PATH \
    -X POST \
    http://masqued/client?type=upsert \
    --data \
'
{
    "names": ["'"${clientName}"'"]
}
' | jq .ids[0])

genClientCert "$id" "$clientName"

log "info" "Client \"$clientName\" has been created"
