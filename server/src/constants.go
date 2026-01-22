package main

const WORK_DIR = "/opt/masqued"
const CA_DIR = WORK_DIR + "/ca"
const CERT_DIR = WORK_DIR + "/certs"
const SCRIPT_DIR = WORK_DIR + "/scripts"
const CONF_PATH = WORK_DIR + "/masqued.conf"

const SERVER_CA_DIR = CA_DIR + "/server"
const SERVER_CA_PATH = CA_DIR + "/server/certs/ca.cert.pem"
const SERVER_CERT_DIR = CERT_DIR +  "/server"
const SERVER_CERT_PATH = CERT_DIR + "/server/server.crt"
const SERVER_KEY_PATH = CERT_DIR + "/server/server.key"

const CLIENT_CA_DIR = CA_DIR + "/client"
const CLIENT_CA_PATH = CA_DIR + "/client/certs/ca.cert.pem"
const CLIENT_CERT_DIR = CERT_DIR + "/client"
