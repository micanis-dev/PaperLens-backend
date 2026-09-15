package config

import "testing"

func TestParseDevTestUsers(t *testing.T) {
	users := parseDevTestUsers("one:First, two:Second, malformed, :missing-id, three:")
	if len(users) != 2 || users[0].ID != "one" || users[0].Label != "First" || users[1].ID != "two" {
		t.Fatalf("users=%+v", users)
	}
}

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
