package spf

import (
	"regexp"
	"testing"
)

func TestGetDomainSPF(t *testing.T) {
	r := NewRootSPF("", mockLookup{})
	// Check that correctly filters TXT records for SPF record
	record, _ := GetDomainSPFRecord("mydomain", r.LookupIF)
	if record != "v=spf1 a ~all" {
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
	domain, record := "mydomain", "v=spf1 a ~all"
	// Check that SPF record matches expected whether or not provided in input
	for _, inputSPF := range []string{"", record} {
		checkedRecord, err := CheckSPFRecord(domain, inputSPF, r.LookupIF)
		if checkedRecord != record {
			t.Fatalf("SPF record lookup did not match expected. Expected `%s` but got `%s`", record, checkedRecord)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Check that returns error when SPF record does not match expected format
	_, err := CheckSPFRecord(domain, "spf1 a ~all", r.LookupIF)
	if !regexp.MustCompile("^.*did not match expected format.*$").MatchString(err.Error()) {
		t.Fatal("SPF record check should have failed")
	}
}

func TestCompareRecords(t *testing.T) {
	// Check that correctly returns differences between string entries (if any)
	start := "a b d e"
	end := "a b c e f g"
	same, inStart, inEnd := CompareRecords(start, end)
	if same {
		t.Fatal("Lists should not match")
	}
	expInStart := "d"
	expInEnd := "c f g"
	if inStart != expInStart || inEnd != expInEnd {
		t.Fatalf("Expected: inStart: %s\n\tinEnd: %s\nGot: inStart: %s\n\tinEnd: %s", expInStart, expInEnd, inStart, inEnd)
	}
}

// TODO: test exporting works
