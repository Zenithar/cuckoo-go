package cuckoo

// ReportFormat defines the possible report format
type ReportFormat string

var (
	// ReportJSON defines the json report format
	ReportJSON ReportFormat = "json"
	// ReortMAEC defines the maec report format
	ReortMAEC ReportFormat = "maec"
	// ReportMETADATA defines the json report format
	ReportMETADATA ReportFormat = "metadata"
	// ReportALL defines the all report format
	ReportALL ReportFormat = "all"
)

// FileCreateResponse is the reponse on file submit
type FileCreateResponse struct {
	TaskIDs []int32  `json:"task_ids"`
	URLs    []string `json:"url"`
	Data    string   `json:"data"`
	Error   bool     `json:"error"`
}
