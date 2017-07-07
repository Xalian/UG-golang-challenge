package filters

import (
	"reflect"
	"testing"

	"github.com/xalian/ugchallenge/jsonvuln"
)

func TestFilterLimit(t *testing.T) {
	validOutput := []jsonvuln.Vuln{
		jsonvuln.Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		jsonvuln.Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}

	badInput := []jsonvuln.Vuln{
		jsonvuln.Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		jsonvuln.Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"},
		jsonvuln.Vuln{ID: 9,
			Severity: 1,
			Title:    "FakeInc routers vulnerable to 0-day exploit",
			Date:     "2015-04-21"}}
	type args struct {
		limit int
		vulns []jsonvuln.Vuln
	}
	tests := []struct {
		name string
		args args
		want []jsonvuln.Vuln
	}{
		{name: "Test",
			args: args{limit: 2, vulns: badInput},
			want: validOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterLimit(tt.args.limit, tt.args.vulns); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterLimit() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterDate(t *testing.T) {
	validOutput := []jsonvuln.Vuln{
		jsonvuln.Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		jsonvuln.Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}

	badInput := []jsonvuln.Vuln{
		jsonvuln.Vuln{ID: 9,
			Severity: 1,
			Title:    "FakeInc routers vulnerable to 0-day exploit",
			Date:     "2015-04-21"},
		jsonvuln.Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		jsonvuln.Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}
	type args struct {
		limitDate string
		vulns     []jsonvuln.Vuln
	}
	tests := []struct {
		name string
		args args
		want []jsonvuln.Vuln
	}{
		{name: "Test",
			args: args{limitDate: "2015-04-22", vulns: badInput},
			want: validOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterDate(tt.args.limitDate, tt.args.vulns); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterDate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterSeverity(t *testing.T) {
	validOutput := []jsonvuln.Vuln{
		jsonvuln.Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		jsonvuln.Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}

	badInput := []jsonvuln.Vuln{
		jsonvuln.Vuln{ID: 9,
			Severity: 1,
			Title:    "FakeInc routers vulnerable to 0-day exploit",
			Date:     "2015-04-21"},
		jsonvuln.Vuln{ID: 1,
			Severity: 9,
			Title:    "Multiple cross-site scripting (XSS) vulnerabilities in AbleSpace 1.0",
			Date:     "2016-07-04"},
		jsonvuln.Vuln{ID: 2,
			Severity: 5,
			Title:    "Multiple PHP remote file inclusion vulnerabilities in GoSamba",
			Date:     "2016-02-17"}}
	type args struct {
		severity int
		vulns    []jsonvuln.Vuln
	}
	tests := []struct {
		name string
		args args
		want []jsonvuln.Vuln
	}{
		{name: "Test",
			args: args{severity: 4, vulns: badInput},
			want: validOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterSeverity(tt.args.severity, tt.args.vulns); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterSeverity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_min(t *testing.T) {
	type args struct {
		a int
		b int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{name: "TestEqual",
			args: args{a: 10, b: 10},
			want: 10},
		{name: "Test",
			args: args{a: 10, b: 3},
			want: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := min(tt.args.a, tt.args.b); got != tt.want {
				t.Errorf("min() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dateSince(t *testing.T) {
	type args struct {
		date  string
		limit string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "TestFalseDay",
			args: args{date: "2015-06-15", limit: "2015-06-16"},
			want: false},
		{name: "TestFalseMonth",
			args: args{date: "2015-06-15", limit: "2015-07-14"},
			want: false},
		{name: "TestFalseYear",
			args: args{date: "2015-06-15", limit: "2016-06-14"},
			want: false},
		{name: "TestTrue",
			args: args{date: "2015-06-15", limit: "2015-06-14"},
			want: true},
		{name: "TestTreEqual",
			args: args{date: "2015-06-15", limit: "2015-06-15"},
			want: true}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dateSince(tt.args.date, tt.args.limit); got != tt.want {
				t.Errorf("dateSince() = %v, want %v", got, tt.want)
			}
		})
	}
}
