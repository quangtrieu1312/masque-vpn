package domain

type DHCP struct {
    ID int64 `json:"id"`
    FirstIP int64 `json:"first_ip"`
    LastIP int64 `json:"last_ip"`
}
