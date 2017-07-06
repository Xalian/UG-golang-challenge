package filters

import (
	"github.com/xalian/ugchallenge/jsonvuln"
)

func filterLimit(limit int, vulns []jsonvuln.Vuln) []jsonvuln.Vuln {
	limit = max(limit, len(vulns))
	return vulns[0 : limit-1]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
