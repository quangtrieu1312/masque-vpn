package request

type ResetDHCP struct {
    FirstIP int64 `json:"fist_ip"`
    LastIP int64 `json:"last_ip"`
}
