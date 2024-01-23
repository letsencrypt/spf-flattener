package main

import (
	"fmt"
	"net"
	"regexp"
	"testing"
)

// MOCK DATA & HELPER FUNCTIONS ===============================================================

var TXT_LOOKUP = map[string][]string{
	"mydomain":    {"NOT AN SPF RECORD", "v=spf1 a ~all"},
	"test.com":    {"v=spf1 ip4:10.10.10.10", "exp='IDK why that failed, good luck'"},
	"example.com": {"v=spf1 include:mydomain exp=exp.example.com"},
	"nospf":       {"NOT AN SPF RECORD", "v=also not an spf record"},
}

var IP_LOOKUP = map[string][]net.IP{
	"mydomain":                               {net.IP{0, 0, 0, 0}, net.IP{1, 2, 3, 4}},
	"example.com":                            {net.ParseIP("2001:db8::68")},
	"abcd.net":                               {net.IP{12, 34, 56, 78}, net.ParseIP("2001:db8::1"), net.IP{6, 6, 6, 6}},
	"info.info":                              {net.IP{1, 1, 1, 1}, net.IP{2, 2, 2, 2}, net.IP{3, 3, 3, 3}, net.ParseIP("1:2:3:4:5:6:7:8")},
	"longer.domain/subdomain/subsubdomain/a": {net.ParseIP("1234:34::1")},
}
var MX_LOOKUP = map[string][]*net.MX{
	"anotherdomain": {&net.MX{Host: "mydomain", Pref: 10}},
	"test.org":      {&net.MX{Host: "example.com", Pref: 20}, &net.MX{Host: "abcd.net", Pref: 10}},
	"test.domain":   {&net.MX{Host: "example.com", Pref: 10}, &net.MX{Host: "info.info", Pref: 30}},
}

func mockLookupTXT(s string) ([]string, error) {
	return TXT_LOOKUP[s], nil
}

func mockLookupIP(s string) ([]net.IP, error) {
	return IP_LOOKUP[s], nil
}

func mockLookupMX(s string) ([]*net.MX, error) {
	return MX_LOOKUP[s], nil
}

// Check if input error is nil, if ALL_MECHANISM is expected, and if MAP_IPS and MAP_NONFLAT have the expected entries.
func compareExpected(err error, expAll string, expIPs, expNF []string) error {
	if err != nil {
		return fmt.Errorf("unexpected error:\n %s", err)
	}
	if ALL_MECHANISM != expAll {
		return fmt.Errorf("expected `%s` for ALL_MECHANISM but got `%s`", expAll, ALL_MECHANISM)
	}
	for _, expIP := range expIPs {
		if _, ok := MAP_IPS[expIP]; !ok {
			return fmt.Errorf("expected `%s` in MAP_IPS but not found", expIP)
		}
	}
	for _, expNF := range expNF {
		if _, ok := MAP_NONFLAT[expNF]; !ok {
			return fmt.Errorf("expected `%s` in MAP_NONFLAT but not found", expNF)
		}
	}
	return nil
}

// TESTS FOR parseMechanism() =================================================================

func TestParseMechanismAll(t *testing.T) {
	ROOT_DOMAIN = "myrootdomain"
	// Test `all`` mechanism set if domain is root
	_, err := parseMechanism("~all", "myrootdomain", true)
	if err = compareExpected(err, " ~all", []string{}, []string{}); err != nil {
		t.Fatal(err)
	}
	// Test `all`` mechanism is ignored if domain is NOT root
	_, err = parseMechanism("-all", "NOTmyrootdomain", true)
	if err = compareExpected(err, " ~all", []string{}, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismIP(t *testing.T) {
	MAP_IPS = make(map[string]bool)
	// Test ip mechanisms of the form `ip4:<ipaddr>`, `ip4:<ipaddr>/<prefix-length>, `ip6:<ipaddr>`, and `ip6:<ipaddr>/<prefix-length>`
	ipMechs := []string{"ip4:abcd", "ip4:8.8.8.8", "ip6:efgh/36", "ip6:2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ip6:11:22::33/128"}
	for _, mech := range ipMechs {
		_, err := parseMechanism(mech, "", false)
		if err = compareExpected(err, ALL_MECHANISM, []string{mech}, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismA(t *testing.T) {
	LOOKUP_IP_FUNC = mockLookupIP
	// Test `a` mechanism of the form `a`, `a:<domain>`, `a/<prefix-length>`, and `a:<domain>/<prefix-length`
	testInputs := [][]string{ //mechanism, prefix, aDomain, currentDomain
		{"a", "", "mydomain", "mydomain"},
		{"a:abcd.net", "", "abcd.net", "differentdomain"},
		{"a/24", "/24", "longer.domain/subdomain/subsubdomain/a", "longer.domain/subdomain/subsubdomain/a"},
		{"a:info.info/46", "/46", "info.info", "differentdomain"},
	}
	for _, testCase := range testInputs {
		MAP_IPS = make(map[string]bool)
		expIPs := []string{}
		for _, ip := range IP_LOOKUP[testCase[2]] {
			expIPs = append(expIPs, "ip"+IPV[len(ip)]+":"+ip.String()+testCase[1])
		}
		_, err := parseMechanism(testCase[0], testCase[3], false)
		if err = compareExpected(err, ALL_MECHANISM, expIPs, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismMX(t *testing.T) {
	LOOKUP_IP_FUNC = mockLookupIP
	LOOKUP_MX_FUNC = mockLookupMX
	// Test `mx` mechanism of the form `mx`, `mx:<domain>`, `mx/<prefix-length>`, and `mx:<domain>/<prefix-length`
	testInputs := [][]string{ // mechanism, prefix, mxDomain, currentDomain
		{"mx", "", "anotherdomain", "anotherdomain"},
		{"mx:test.org", "", "test.org", "differentdomain"},
		{"mx/19", "/19", "test.domain", "test.domain"},
		{"mx:anotherdomain/6", "/6", "anotherdomain", "differentdomain"},
	}
	for _, testCase := range testInputs {
		MAP_IPS = make(map[string]bool)
		expIPs := []string{}
		for _, d := range MX_LOOKUP[testCase[2]] {
			for _, ip := range IP_LOOKUP[d.Host] {
				expIPs = append(expIPs, "ip"+IPV[len(ip)]+":"+ip.String()+testCase[1])
			}
		}
		_, err := parseMechanism(testCase[0], testCase[3], false)
		if err = compareExpected(err, ALL_MECHANISM, expIPs, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismNonFlat(t *testing.T) {
	MAP_NONFLAT = make(map[string]bool)
	// Test ptr mechanism of the form `ptr`
	_, err := parseMechanism("ptr", "domain", false)
	if err = compareExpected(err, ALL_MECHANISM, []string{}, []string{"ptr:domain"}); err != nil {
		t.Fatal(err)
	}
	// Test nonflat mechanisms of the form `ptr:<domain>`, `<exists:<domain>`, and `exp=<domain>`
	nfMechs := []string{"ptr:example.com", "exists:yourdomain", "exp=explain.example.com"}
	for _, nfMech := range nfMechs {
		_, err := parseMechanism(nfMech, "", false)
		if err = compareExpected(err, ALL_MECHANISM, []string{}, []string{nfMech}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismInclude(t *testing.T) {
	LOOKUP_TXT_FUNC = mockLookupTXT
	LOOKUP_IP_FUNC = mockLookupIP
	MAP_IPS = make(map[string]bool)
	// Test mechanism of the form `include:<domain>`
	includeDomain := "mydomain" // SPF record is just `a`, so expect IPs for "mydomain"
	expIPs := []string{}
	for _, ip := range IP_LOOKUP[includeDomain] {
		expIPs = append(expIPs, "ip"+IPV[len(ip)]+":"+ip.String())
	}
	_, err := parseMechanism("include:"+includeDomain, "notmydomain", false)
	if err = compareExpected(err, ALL_MECHANISM, expIPs, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismRedirect(t *testing.T) {
	MAP_IPS = make(map[string]bool)
	LOOKUP_TXT_FUNC = mockLookupTXT
	LOOKUP_IP_FUNC = mockLookupIP
	// Test mechanism of the form `redirect=<domain>`
	redirectDomain := "test.com" // SPF record is just ip4:10.10.10.10
	_, err := parseMechanism("redirect="+redirectDomain, "notmydomain", false)
	if err = compareExpected(err, ALL_MECHANISM, []string{"ip4:10.10.10.10"}, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismFails(t *testing.T) {
	// Test that parseMechanism fails on unexpected mechanism or syntax error
	noMatchRegex := regexp.MustCompile("^(received unexpected SPF mechanism or syntax:).*$")
	for _, wrongMech := range []string{"redirect:domain", "include=anotherdomain", "ip:0.0.0.0", "1.1.1.1", "", "ip6", "exp:explanation", "notMechanism:hello"} {
		_, err := parseMechanism(wrongMech, "", false)
		if !noMatchRegex.MatchString(err.Error()) {
			t.Fatalf("Expected `unexpected SPF mechanism or syntax` error, got `%s` instead", err)
		}
	}
}

// TESTS FOR flattenSPF() =====================================================================

func TestFlattenSPF(t *testing.T) {
	MAP_IPS = make(map[string]bool)
	MAP_NONFLAT = make(map[string]bool)
	LOOKUP_IP_FUNC = mockLookupIP
	LOOKUP_MX_FUNC = mockLookupMX
	LOOKUP_TXT_FUNC = mockLookupTXT
	// Test that SPF record with multiple different entries gets flattened as expected
	domain, spf := "abcd.net", "v=spf1 ip4:0.0.0.0/24 include:example.com ip6:56:0::0:7 a mx:test.domain exists:somedomain.edu -all"
	// ip4, ip6, exists provided
	// include:example.com --> (mydomain spf --> a --> mydomain IPs) + exp=exp.example.com
	// a --> abcd.net IPs
	// mx:test.domain --> example.com IPs and info.info IPs
	ROOT_DOMAIN = domain
	expIPs := []string{"ip4:0.0.0.0/24", "ip6:56:0::0:7"}
	expNFs := []string{"exists:somedomain.edu", "exp=exp.example.com"}
	for _, d := range []string{"mydomain", "abcd.net", "info.info", "example.com"} {
		for _, ip := range IP_LOOKUP[d] {
			expIPs = append(expIPs, "ip"+IPV[len(ip)]+":"+ip.String())
		}
	}
	err := flattenSPF(domain, spf)
	if err = compareExpected(err, " -all", expIPs, expNFs); err != nil {
		t.Fatal(err)
	}
}

func TestFlattenRedirects(t *testing.T) {
	LOOKUP_IP_FUNC = mockLookupIP
	LOOKUP_TXT_FUNC = mockLookupTXT
	MAP_IPS = make(map[string]bool)
	domain, spf := "somedomain", "v=spf1 ip4:9.9.9.9 redirect=mydomain ip6:2:2:2:2::::"
	// Test that mechanisms after redirects are ignored
	expIPs := []string{"ip4:9.9.9.9"}
	for _, ip := range IP_LOOKUP["mydomain"] {
		expIPs = append(expIPs, "ip"+IPV[len(ip)]+":"+ip.String())
	}
	err := flattenSPF(domain, spf)
	if err = compareExpected(err, ALL_MECHANISM, expIPs, []string{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := MAP_IPS["ip6:2:2:2:2::::"]; ok {
		t.Fatal("Mechanisms after redirect should have been ignored")
	}
	// Test that redirects are ignored if SPF record includes `all` mechanism
	MAP_IPS = make(map[string]bool)
	err = flattenSPF(domain, spf+" ~all")
	if err = compareExpected(err, ALL_MECHANISM, []string{"ip4:9.9.9.9"}, []string{}); err != nil {
		t.Fatal(err)
	}
	if len(MAP_IPS) > 1 {
		t.Fatal("Redirect should have been ignored since `all` mechanism in SPF record")
	}
}

// TESTS FOR OTHER SPF FLATTENING FUNCTIONS ===================================================

func TestGetDomainSPF(t *testing.T) {
	LOOKUP_TXT_FUNC = mockLookupTXT
	// Check that correctly filters TXT records for SPF record
	record, _ := getDomainSPFRecord("mydomain")
	if record != "v=spf1 a ~all" {
		t.Fatal("Filtering for SPF record failed.")
	}
	// Check that returns error when no SPF record found
	_, err := getDomainSPFRecord("nospf")
	if !regexp.MustCompile("^no SPF record found for.*$").MatchString(err.Error()) {
		t.Fatal("Should have failed to find SPF record for `nospf`")
	}
}

func TestCheckDomainSPF(t *testing.T) {
	LOOKUP_TXT_FUNC = mockLookupTXT
	domain, record := "mydomain", "v=spf1 a ~all"
	// Check that SPF record matches expected whether or not provided in input
	for _, inputSPF := range []string{"", record} {
		checkedRecord, err := checkSPFRecord(domain, inputSPF)
		if checkedRecord != record {
			t.Fatalf("SPF record lookup did not match expected. Expected `%s` but got `%s`", record, checkedRecord)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Check that returns error when SPF record does not match expected format
	_, err := checkSPFRecord(domain, "spf1 a ~all")
	if !regexp.MustCompile("^.*did not match expected format.*$").MatchString(err.Error()) {
		t.Fatal("SPF record check should have failed")
	}
}

func TestWriteFlatSPF(t *testing.T) {
	MAP_IPS = map[string]bool{"ip4:0.0.0.0": true, "ip6:1:1:1:1::::": true}
	MAP_NONFLAT = map[string]bool{"exists:domain": true, "ptr": true, "exists:anotherdomain": true}
	ALL_MECHANISM = " -all"
	expectedSPF := "v=spf1 ip4:0.0.0.0 ip6:1:1:1:1:::: exists:domain ptr exists:anotherdomain -all"

	// Check that written SPF record starts with `v=sfp1` and ends with `all` mechanism
	outputSPF := writeFlatSPF()
	if regexp.MustCompile("^(v=spf1).* (/-all)$").MatchString(outputSPF) {
		t.Fatalf("SFP record should start with 'v=sfp1' and end with `all` mechanism if set.\nGot: `%s`", outputSPF)
	}
	// Check that both SPF records have the same entries (order doesn't matter)
	if matched, inStart, inEnd := compareRecords(expectedSPF, outputSPF); !matched {
		t.Fatalf("SPF record does not include expected entries. Should include `%s` and should not include `%s`", inStart, inEnd)
	}
}

// TESTS FOR INPUT/OUTPUT FUNCTIONS ===========================================================

func TestCompareRecords(t *testing.T) {
	// Check that correctly returns differences between string entries (if any)
	start := "a b d e"
	end := "a b c e f g"
	same, inStart, inEnd := compareRecords(start, end)
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
// TODO: add more tests for fail cases
