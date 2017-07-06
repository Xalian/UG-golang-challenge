package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"strconv"

	"github.com/xalian/ugchallenge/filters"
	"github.com/xalian/ugchallenge/jsonvuln"
)

func main() {

	portPtr := flag.String("port", ":8080", "the port the program listens to. Default :8080")
	fileNamePtr := flag.String("file", "data/data.json", "the path of the JSON file. Default data/data.json")
	flag.Parse()

	vulns := jsonvuln.RemoveMalformedInput(jsonvuln.ParseJSON(*fileNamePtr))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { filterHandler(w, r, vulns) })
	http.ListenAndServe(*portPtr, nil)
}

func filterHandler(w http.ResponseWriter, r *http.Request, vulns []jsonvuln.Vuln) {
	limit := r.URL.Query().Get("limit")
	minSeverity := r.URL.Query().Get("severity_at_least")
	since := r.URL.Query().Get("since")

	if minSeverity != "" {
		sev, err := strconv.Atoi(minSeverity)
		if err == nil {
			vulns = filters.FilterSeverity(sev, vulns)
		}
	}
	if since != "" {
		//TODO: check valid date format
		vulns = filters.FilterDate(since, vulns)
	}
	if limit != "" {
		lmt, err := strconv.Atoi(limit)
		if err == nil {
			vulns = filters.FilterLimit(lmt, vulns)
		}
	}
	json.NewEncoder(w).Encode(vulns)
}
