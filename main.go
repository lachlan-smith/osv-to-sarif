package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

type Vulnerability []struct {
	OSV     Entry    `json:"osv"`
	Modules []Module `json:"modules"`
}

func main() {
	if len(os.Args) < 2 {
		log.Panicf("input filename must be provided")
	}

	file, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	vulnerabilities := Vulnerability{}
	json.Unmarshal(file, &vulnerabilities)

	report, err := sarif.New(sarif.Version210)
	if err != nil {
		panic(err)
	}

	run := sarif.NewRunWithInformationURI("govulncheck", "https://vuln.go.dev")

	for i, v := range vulnerabilities {
		run.AddRule(v.OSV.ID).
			WithName(v.OSV.ID).
			WithShortDescription(sarif.NewMultiformatMessageString(v.OSV.Details)).
			WithFullDescription(sarif.NewMultiformatMessageString(v.OSV.Details)).
			WithHelpURI(v.OSV.DatabaseSpecific.URL).WithProperties(sarif.Properties{
			"aliases": v.OSV.Aliases,
		})

		for _, m := range v.Modules {
			for _, p := range m.Packages {
				if len(p.Callstacks) == 0 {
					msg := fmt.Sprintf("package %s has a known vulnerability: %s, however the codebase doesn't call the vulnerable function directly.", p.Path, v.OSV.ID)
					result := sarif.NewRuleResult(v.OSV.ID).
						WithLevel("warning").
						WithMessage(sarif.NewTextMessage(msg))
					location := sarif.NewLocation().
						WithPhysicalLocation(sarif.NewPhysicalLocation().
							WithArtifactLocation(sarif.NewSimpleArtifactLocation("go.mod")))
					result.WithLocations([]*sarif.Location{location})
					result.WithRuleIndex(i)
					run.AddResult(result)
				} else {
					for _, c := range p.Callstacks {
						msg := fmt.Sprintf("package %s has a known vulnerability: %s", p.Path, v.OSV.ID)
						result := sarif.NewRuleResult(v.OSV.ID).
							WithLevel("error").
							WithMessage(sarif.NewTextMessage(msg))
						region := sarif.NewRegion().
							WithStartLine(c.Frames[0].Position.Line).
							WithStartColumn(c.Frames[0].Position.Column).
							WithCharOffset((c.Frames[0].Position.Offset))
						location := sarif.NewLocation().
							WithPhysicalLocation(sarif.NewPhysicalLocation().
								WithArtifactLocation(sarif.NewSimpleArtifactLocation(c.Frames[0].Position.Filename)).
								WithRegion(region))
						result.WithLocations([]*sarif.Location{location})
						result.WithRuleIndex(i)
						run.AddResult(result)
					}
				}
			}
		}
	}

	report.AddRun(run)
	if err := report.WriteFile("report.sarif"); err != nil {
		panic(err)
	}
}
