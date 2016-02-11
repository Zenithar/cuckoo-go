package cuckoo

// Based on VirusTotal golang client
// https://github.com/williballenthin/govt/blob/master/govt.go

// Client interacts with the services provided by Cuckoo sandbox
type Client interface {
	FileCreate(filePath string) (*FileCreateResponse, error)
	/*URLCreate(url string)
	FileView(hash string)
	TaskSearch(hash string)
	ExtendedTaskSearch()
	TaskList()
	TaskView(taskID string)
	RescheduleTask(taskID string)
	DeleteTask(taskID string)
	TaskStatus(taskID string)
	TaskReport(taskID string, format ReportFormat)
	TaskIOC(taskID string)
	TaskAllScreenshots(taskID string)
	TaskOneScreenShot(taskID string, number int)
	TaskPCAP(taskID string)
	TaskDroppedFiles(taskID string)
	TaskSuricataFiles(taskID string)
	TaskAllProcessDumps(taskID string)
	TaskProcessDump(taskID string, pid int)
	TaskFullMemoryDump(taskID string)
	SampleDownloadByTask(taskID string)
	SampleDownloadByHash(hash string)
	VirtualMachineList()
	VirtualMachineView(name string)
	CuckooStatus()*/
}

type client struct {
	BaseURL           string
	BasicAuthUsername string
	BasicAuthPassword string
}

// -----------------------------------------------------------------------------

func NewClient(baseURL string) Client {
	return &client{
		BaseURL: baseURL,
	}
}

func NewClientWithBasicAuthentication(baseURL string, username, password string) Client {
	return &client{
		BaseURL:           baseURL,
		BasicAuthUsername: username,
		BasicAuthPassword: password,
	}
}

// -----------------------------------------------------------------------------

// FileCreate asks VT to analysis on the specified file, thats also uploaded.
func (c *client) FileCreate(file string) (*FileCreateResponse, error) {
	r := &FileCreateResponse{}
	err := c.fetchApiJson("FILE", "tasks/create/file/", Parameters{"filename": file}, r)
	return r, err
}
