package request

type Resource struct {
	Name string `json:"name"`
	Value string `json:"value"`
}

type DeleteResources struct {
    IDs []int64 `json:"ids"`
}

type UpsertResources struct {
    Resources []Resource `json:"resources"`
}

type UpdateResourceName struct {
    Name string `json:"name"`
}
