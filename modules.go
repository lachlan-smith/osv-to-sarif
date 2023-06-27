package main

type Module struct {
	Path         string          `json:"path"`
	FoundVersion string          `json:"found_version"`
	FixedVersion string          `json:"fixed_version"`
	Packages     []ModulePackage `json:"packages"`
}

type ModulePackage struct {
	Path       string             `json:"path"`
	Callstacks []PackageCallstack `json:"callstacks"`
}

type PackageCallstack struct {
	Frames []CallstackFrame `json:"frames"`
}

type CallstackFrame struct {
	Package  string        `json:"package"`
	Function string        `json:"function"`
	Position FramePosition `json:"position"`
}

type FramePosition struct {
	Filename string `json:"filename"`
	Offset   int    `json:"offset"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}
