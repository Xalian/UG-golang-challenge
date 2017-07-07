package jsonvuln

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
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

//RemoveMalformedInput removes structs will nil values from JSON conversion
func RemoveMalformedInput(vulns []Vuln) []Vuln {

	var validDate = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	sanitised := new([]Vuln)
	for _, value := range vulns {
		if value.ID != 0 && value.Severity != 0 && value.Title != "" && value.Date != "" {
			if validDate.MatchString(value.Date) {
				*sanitised = append(*sanitised, value)
			}
		}
		//TODO: Log erronous input?
	}

	return *sanitised
}
