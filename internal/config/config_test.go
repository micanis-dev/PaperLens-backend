package config

import "testing"

func TestRequireHTTPSURL(t *testing.T) {
	if err := requireHTTPSURL("FRONTEND_BASE_URL", "https://paperlens.example"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"http://paperlens.example", "https://", "paperlens.example", ""} {
		if err := requireHTTPSURL("URL", value); err == nil {
			t.Fatalf("accepted non-HTTPS URL %q", value)
		}
	}
}
