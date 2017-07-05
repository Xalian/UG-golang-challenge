package vulnParser

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

//ParseJSON returns the JSON in the given file
func ParseJSON(fileName string) *[]Vuln {

	dataFile, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)

	}

	jsonParser := json.NewDecoder(dataFile)
	json := new([]Vuln)
	if err = jsonParser.Decode(json); err != nil {
		log.Fatal(err)
	}
	return json
}
