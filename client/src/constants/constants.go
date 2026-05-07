package constants

const WORK_DIR = "/etc/masque"
const CERT_DIR = WORK_DIR + "/certs"

const SCRIPT_DIR = WORK_DIR + "/scripts"
const BOOTSTRAP_SCRIPT_PATH = SCRIPT_DIR + "/bootstrap/main.sh"
const POSTUP_SCRIPT_PATH = SCRIPT_DIR + "/postup/main.sh"
const PREDOWN_SCRIPT_PATH = SCRIPT_DIR + "/predown/main.sh"
const CONF_PATH = WORK_DIR + "/masque.conf"

const SERVER_CA_PATH = CERT_DIR + "/ca.crt"
const CLIENT_CERT_PATH = CERT_DIR + "/client.crt"
const CLIENT_KEY_PATH = CERT_DIR + "/client.key"

const LOG_PATH = "/var/log/masque.log"
