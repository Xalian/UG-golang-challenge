package filters

import (
	"strconv"
	"strings"

	"github.com/xalian/ugchallenge/jsonvuln"
)

func FilterLimit(limit int, vulns []jsonvuln.Vuln) []jsonvuln.Vuln {
	limit = max(limit, len(vulns))
	return vulns[0 : limit-1]
}

func FilterDate(limitDate string, vulns []jsonvuln.Vuln) []jsonvuln.Vuln {
	filtered := new([]jsonvuln.Vuln)
	for _, value := range vulns {
		if dateSince(value.Date, limitDate) {
			*filtered = append(*filtered, value)
		}
	}
	return *filtered
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

//dateSince checks if date is later than limit
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
	case dateDay > limitDay:
		return true
	case dateDay < limitDay:
		return false
	}
	return false
}
