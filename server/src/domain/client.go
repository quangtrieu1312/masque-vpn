package domain

type Client struct {
    ID int64 `json:"id"`
    Name string `json:"name"`
    IP string `json:"ip"`
    LastSeen uint64 `json:"last_seen"`
}
