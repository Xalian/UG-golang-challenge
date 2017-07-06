package main

import (
	"flag"
	"net/http"

	"github.com/xalian/ugchallenge/jsonvuln"
)

func main() {

	portPtr := flag.String("port", ":8080", "the port the program listens to. Default :8080")
	fileNamePtr := flag.String("file", "data/data.json", "the path of the JSON file. Default data/data.json")
	flag.Parse()

	vulns := new([]jsonvuln.Vuln)

	http.HandleFunc("/", FilterHandler)
	http.ListenAndServe(*portPtr, nil)
}
