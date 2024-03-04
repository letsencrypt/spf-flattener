package spf

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

func compareExpectedLogLevel(input string, expLevel slog.Level) error {
	level, err := GetLogLevel(input)
	if err != nil {
		return fmt.Errorf("unexpected failure parsing log level")
	}
	if level != expLevel {
		return fmt.Errorf("expected to get %s, instead got %s", expLevel, level)
	}
	return nil
}

func TestGetLogLevel(t *testing.T) {
	for _, input := range []string{"warn", "Warn", "LevelWarn", "levelwarn"} {
		if err := compareExpectedLogLevel(input, slog.LevelWarn); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"debug", "Debug", "LevelDebug", "leveldebug"} {
		if err := compareExpectedLogLevel(input, slog.LevelDebug); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"error", "Error", "LevelError", "levelerror"} {
		if err := compareExpectedLogLevel(input, slog.LevelError); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"info", "Info", "LevelInfo", "LevelInfo"} {
		if err := compareExpectedLogLevel(input, slog.LevelInfo); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"INFO", "", "ErrorLevel", "err", "debugmode", "notaloglevel"} {
		if _, err := GetLogLevel(input); !strings.HasPrefix(err.Error(), "unexpected log level") {
			t.Fatalf("expected to fail getting log level for %s", input)
		}
	}
}

func TestGetDomainSPF(t *testing.T) {
	r := NewRootSPF("", mockLookup{})
	// Check that correctly filters TXT records for SPF record
	if record, _ := GetDomainSPFRecord("mydomain", r.LookupIF); record != "v=spf1 a ~all" {
		t.Fatal("Filtering for SPF record failed.")
	}
	// Check that returns error when no SPF record found
	_, err := GetDomainSPFRecord("nospf", r.LookupIF)
	if !regexp.MustCompile("^no SPF record found for.*$").MatchString(err.Error()) {
		t.Fatal("Should have failed to find SPF record for `nospf`")
	}
}

func TestCheckDomainSPF(t *testing.T) {
	r := NewRootSPF("", mockLookup{})
	// Check that returns error when SPF record does not match expected format
	err := CheckSPFRecord("mydomain", "spf1 a ~all", r.LookupIF)
	if !regexp.MustCompile("^.*did not match expected format.*$").MatchString(err.Error()) {
		t.Fatal("SPF record check should have failed")
	}
}

func TestCompareRecords(t *testing.T) {
	// Check that correctly returns when same
	same, _, _ := CompareRecords("a b c", "b c a")
	if !same {
		t.Fatal("Lists should match")
	}
	// Check that correctly returns differences between string entries (if any)
	testInputs := [][]string{ // start, end, expInStart, expInEnd
		{"a b c", "d e f", "a b c", "d e f"},
		{"e b d a", "a b c e f g", "d", "c f g"},
		{"a b c e f g", "e b d a", "c f g", "d"},
		{"ip4:1.1.1.1 include:mydomain ptr exp=\"some explanation\"", "ip4:1.2.3.4 ip4:1.1.1.1 ptr exp=\"some explanation\"", "include:mydomain", "ip4:1.2.3.4"},
	}
	for _, testCase := range testInputs {
		same, inStart, inEnd := CompareRecords(testCase[0], testCase[1])
		if same {
			t.Fatal("Lists should not match")
		}
		if inStart != testCase[2] || inEnd != testCase[3] {
			t.Fatalf("Expected: inStart: %s\n\tinEnd: %s\nGot: inStart: %s\n\tinEnd: %s", testCase[2], testCase[3], inStart, inEnd)
		}
	}
}

// TODO: test exporting works
