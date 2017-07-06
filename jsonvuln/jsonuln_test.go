package jsonvuln

import (
	"reflect"
	"testing"
)

func TestParseJSON(t *testing.T) {

	validTest := []Vuln{
		Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}

	badInput := []Vuln{
		Vuln{ID: 0,
			Severity: 1,
			Title:    "FakeInc routers vulnerable to 0-day exploit",
			Date:     "2015-01-22"},
		Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}

	type args struct {
		fileName string
	}

	tests := []struct {
		name string
		args args
		want *[]Vuln
	}{
		{name: "ValidTest",
			args: args{fileName: "../data/validtest.json"},
			want: &validTest},

		{name: "Bad Input",
			args: args{fileName: "../data/badinput.json"},
			want: &badInput}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseJSON(tt.args.fileName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoveMalformedInput(t *testing.T) {
	validOutput := []Vuln{
		Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}

	badInput := []Vuln{
		Vuln{ID: 0,
			Severity: 1,
			Title:    "FakeInc routers vulnerable to 0-day exploit",
			Date:     "2015-01-22"},
		Vuln{ID: 45,
			Severity: 0,
			Title:    "FakeInc routers vulnerable to 0-day exploit",
			Date:     "2015-01-22"},
		Vuln{ID: 6,
			Severity: 1,
			Title:    "",
			Date:     "2015-01-22"},
		Vuln{ID: 9,
			Severity: 1,
			Title:    "FakeInc routers vulnerable to 0-day exploit",
			Date:     ""},
		Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}
	type args struct {
		vulns *[]Vuln
	}
	tests := []struct {
		name string
		args args
		want *[]Vuln
	}{
		{name: "Test",
			args: args{vulns: &badInput},
			want: &validOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoveMalformedInput(tt.args.vulns); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveMalformedInput() = %v, want %v", got, tt.want)
			}
		})
	}
}
