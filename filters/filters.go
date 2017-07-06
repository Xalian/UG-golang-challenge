package filters

import (
	"strconv"
	"strings"

	"github.com/xalian/ugchallenge/jsonvuln"
)

//FilterLimit returns a slice of length limit or the length of vulns, whichever is lower
func FilterLimit(limit int, vulns []jsonvuln.Vuln) []jsonvuln.Vuln {
	limit = min(limit, len(vulns))
	return vulns[0:limit]
}

//FilterDate returns a slice containing only Vulns with dates after the limit
func FilterDate(limitDate string, vulns []jsonvuln.Vuln) []jsonvuln.Vuln {
	filtered := new([]jsonvuln.Vuln)
	for _, value := range vulns {
		if dateSince(value.Date, limitDate) {
			*filtered = append(*filtered, value)
		}
	}
	return *filtered
}

//FilterSeverity returns a slice containing only Vulns with a Severity higher or equal to the limit
func FilterSeverity(severity int, vulns []jsonvuln.Vuln) []jsonvuln.Vuln {
	filtered := new([]jsonvuln.Vuln)
	for _, value := range vulns {
		if value.Severity >= severity {
			*filtered = append(*filtered, value)
		}
	}
	return *filtered
}

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}

//dateSince checks if date is later or equal than limit
func dateSince(date, limit string) bool {

	dateParts := strings.Split(date, "-")
	limitParts := strings.Split(limit, "-")

	dateYear, _ := strconv.Atoi(dateParts[0])
	limitYear, _ := strconv.Atoi(limitParts[0])
	switch {
	case dateYear > limitYear:
		return true
	case dateYear < limitYear:
		return false
	}

	dateMonth, _ := strconv.Atoi(dateParts[1])
	limitMonth, _ := strconv.Atoi(limitParts[1])
	switch {
	case dateMonth > limitMonth:
		return true
	case dateMonth < limitMonth:
		return false
	}

	dateDay, _ := strconv.Atoi(dateParts[2])
	limitDay, _ := strconv.Atoi(limitParts[2])
	switch {
	case dateDay >= limitDay:
		return true
	case dateDay < limitDay:
		return false
	}
	return false
}
