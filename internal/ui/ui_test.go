package ui

import (
	"strings"
	"testing"
)

func TestDashboardContainsProminentRuleBanner(t *testing.T) {
	index, err := files.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("ReadFile(index.html) error = %v", err)
	}
	app, err := files.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("ReadFile(app.js) error = %v", err)
	}

	html := string(index)
	for _, want := range []string{
		`id="ruleBanner"`,
		`id="ruleBannerTitle"`,
		`id="ruleBannerDetail"`,
		`id="ruleBannerAction"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("index.html missing %s", want)
		}
	}

	js := string(app)
	for _, want := range []string{
		"function renderRuleBanner",
		"需要点击“应用规则”",
		"规则正在生效",
		"规则未生效",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js missing %q", want)
		}
	}
}
