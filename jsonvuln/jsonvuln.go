package jsonvuln

import (
	"encoding/json"
	"log"
	"os"
)

//Vuln is how the JSON this program reads should be structured
type Vuln struct {
	ID       int    `json:"id"`
	Severity int    `json:"severity"`
	Title    string `json:"title"`
	Date     string `json:"date_reported"`
}

//ParseJSON returns the JSON in the file found at the given path
func ParseJSON(fileName string) []Vuln {

	dataFile, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}

	jsonParser := json.NewDecoder(dataFile)
	json := new([]Vuln)
	if err = jsonParser.Decode(json); err != nil {
		log.Fatal(err)
	}

	return *json
}

//EncodeVulns returns an array of Vulns as JSON
func EncodeVulns(vulns []Vuln) []byte {

	b, err := json.Marshal(vulns)
	if err != nil {
		log.Fatal(err)
	}

	return b
}

//RemoveMalformedInput removes structs will nil values from JSON conversion
func RemoveMalformedInput(vulns []Vuln) []Vuln {

	sanitised := new([]Vuln)
	for _, value := range vulns {
		if value.ID != 0 && value.Severity != 0 && value.Title != "" && value.Date != "" {
			//TODO: check valid date format
			*sanitised = append(*sanitised, value)
		}
		//TODO: Log erronous input?
	}

	return *sanitised
}
