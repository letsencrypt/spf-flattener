package spf

import (
	"fmt"
	"net"
	"regexp"
	"testing"
)

// MOCK DATA & HELPER FUNCTIONS ===============================================================

type mockLookup struct{}

func (n mockLookup) LookupTXT(s string) ([]string, error) {
	return TXT_LOOKUP[s], nil
}
func (n mockLookup) LookupIP(s string) ([]net.IP, error) {
	return IP_LOOKUP[s], nil
}
func (n mockLookup) LookupMX(s string) ([]*net.MX, error) {
	return MX_LOOKUP[s], nil
}

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

// Check if input error is nil, if r.ALlMechanism is expected, and if r.MapIPs and r.MapNonflat have the expected entries.
func (r *RootSPF) compareExpected(err error, expAll string, expIPs, expNF []string) error {
	if err != nil {
		return fmt.Errorf("unexpected error:\n %s", err)
	}
	if r.AllMechanism != expAll {
		return fmt.Errorf("expected `%s` for r.AllMechanism but got `%s`", expAll, r.AllMechanism)
	}
	for _, expIP := range expIPs {
		if _, ok := r.MapIPs[expIP]; !ok {
			return fmt.Errorf("expected `%s` in r.MapIPs but not found", expIP)
		}
	}
	for _, expNF := range expNF {
		if _, ok := r.MapNonflat[expNF]; !ok {
			return fmt.Errorf("expected `%s` in r.MapNonflat but not found", expNF)
		}
	}
	return nil
}

// TESTS FOR parseMechanism() =================================================================

func TestParseMechanismAll(t *testing.T) {
	r := RootSPF{RootDomain: "myrootdomain", LookupIF: mockLookup{}}
	// Test `all`` mechanism set if domain is root
	err := r.ParseMechanism("~all", "myrootdomain")
	if err = r.compareExpected(err, " ~all", []string{}, []string{}); err != nil {
		t.Fatal(err)
	}
	// Test `all`` mechanism is ignored if domain is NOT root
	err = r.ParseMechanism("-all", "NOTmyrootdomain")
	if err = r.compareExpected(err, " ~all", []string{}, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismIP(t *testing.T) {
	r := RootSPF{MapIPs: map[string]bool{}, LookupIF: mockLookup{}}
	// Test ip mechanisms of the form `ip4:<ipaddr>`, `ip4:<ipaddr>/<prefix-length>, `ip6:<ipaddr>`, and `ip6:<ipaddr>/<prefix-length>`
	ipMechs := []string{"ip4:abcd", "ip4:8.8.8.8", "ip6:efgh/36", "ip6:2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ip6:11:22::33/128"}
	for _, mech := range ipMechs {
		err := r.ParseMechanism(mech, "")
		if err = r.compareExpected(err, "", []string{mech}, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismA(t *testing.T) {
	r := RootSPF{LookupIF: mockLookup{}}
	// Test `a` mechanism of the form `a`, `a:<domain>`, `a/<prefix-length>`, and `a:<domain>/<prefix-length`
	testInputs := [][]string{ //mechanism, prefix, aDomain, currentDomain
		{"a", "", "mydomain", "mydomain"},
		{"a:abcd.net", "", "abcd.net", "differentdomain"},
		{"a/24", "/24", "longer.domain/subdomain/subsubdomain/a", "longer.domain/subdomain/subsubdomain/a"},
		{"a:info.info/46", "/46", "info.info", "differentdomain"},
	}
	for _, testCase := range testInputs {
		r.MapIPs = map[string]bool{}
		expIPs := []string{}
		for _, ip := range IP_LOOKUP[testCase[2]] {
			expIPs = append(expIPs, writeIPMech(ip, testCase[1]))
		}
		err := r.ParseMechanism(testCase[0], testCase[3])
		if err = r.compareExpected(err, "", expIPs, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismMX(t *testing.T) {
	r := RootSPF{LookupIF: mockLookup{}}
	// Test `mx` mechanism of the form `mx`, `mx:<domain>`, `mx/<prefix-length>`, and `mx:<domain>/<prefix-length`
	testInputs := [][]string{ // mechanism, prefix, mxDomain, currentDomain
		{"mx", "", "anotherdomain", "anotherdomain"},
		{"mx:test.org", "", "test.org", "differentdomain"},
		{"mx/19", "/19", "test.domain", "test.domain"},
		{"mx:anotherdomain/6", "/6", "anotherdomain", "differentdomain"},
	}
	for _, testCase := range testInputs {
		r.MapIPs = map[string]bool{}
		expIPs := []string{}
		for _, d := range MX_LOOKUP[testCase[2]] {
			for _, ip := range IP_LOOKUP[d.Host] {
				expIPs = append(expIPs, writeIPMech(ip, testCase[1]))
			}
		}
		err := r.ParseMechanism(testCase[0], testCase[3])
		if err = r.compareExpected(err, "", expIPs, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismNonFlat(t *testing.T) {
	r := RootSPF{MapNonflat: map[string]bool{}, LookupIF: mockLookup{}}
	// Test ptr mechanism of the form `ptr`
	err := r.ParseMechanism("ptr", "domain")
	if err = r.compareExpected(err, "", []string{}, []string{"ptr:domain"}); err != nil {
		t.Fatal(err)
	}
	// Test nonflat mechanisms of the form `ptr:<domain>`, `<exists:<domain>`, and `exp=<domain>`
	nfMechs := []string{"ptr:example.com", "exists:yourdomain", "exp=explain.example.com"}
	for _, nfMech := range nfMechs {
		err := r.ParseMechanism(nfMech, "")
		if err = r.compareExpected(err, "", []string{}, []string{nfMech}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismInclude(t *testing.T) {
	r := RootSPF{MapIPs: map[string]bool{}, LookupIF: mockLookup{}}
	// Test mechanism of the form `include:<domain>`
	includeDomain := "mydomain" // SPF record is just `a`, so expect IPs for "mydomain"
	expIPs := []string{}
	for _, ip := range IP_LOOKUP[includeDomain] {
		expIPs = append(expIPs, writeIPMech(ip, ""))
	}
	err := r.ParseMechanism("include:"+includeDomain, "notmydomain")
	if err = r.compareExpected(err, "", expIPs, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismRedirect(t *testing.T) {
	r := RootSPF{MapIPs: map[string]bool{}, LookupIF: mockLookup{}}
	// Test mechanism of the form `redirect=<domain>`
	redirectDomain := "test.com" // SPF record is just ip4:10.10.10.10
	err := r.ParseMechanism("redirect="+redirectDomain, "notmydomain")
	if err = r.compareExpected(err, "", []string{"ip4:10.10.10.10"}, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismFails(t *testing.T) {
	r := RootSPF{LookupIF: mockLookup{}}
	// Test that parseMechanism fails on unexpected mechanism or syntax error
	noMatchRegex := regexp.MustCompile("^(received unexpected SPF mechanism or syntax:).*$")
	for _, wrongMech := range []string{"redirect:domain", "include=anotherdomain", "ip:0.0.0.0", "1.1.1.1", "", "ip6", "exp:explanation", "notMechanism:hello"} {
		err := r.ParseMechanism(wrongMech, "")
		if !noMatchRegex.MatchString(err.Error()) {
			t.Fatalf("Expected `unexpected SPF mechanism or syntax` error, got `%s` instead", err)
		}
	}
}

// TESTS FOR FlattenSPF() =====================================================================

func TestFlattenSPF(t *testing.T) {
	r := RootSPF{MapIPs: map[string]bool{}, MapNonflat: map[string]bool{}, LookupIF: mockLookup{}}
	// Test that SPF record with multiple different entries gets flattened as expected
	domain, spf := "abcd.net", "v=spf1 ip4:0.0.0.0/24 include:example.com ip6:56:0::0:7 a mx:test.domain exists:somedomain.edu -all"
	// include:example.com --> (mydomain spf --> a --> mydomain IPs) + exp=exp.example.com
	// a --> abcd.net IPs
	// mx:test.domain --> example.com IPs and info.info IPs
	r.RootDomain = domain
	expIPs := []string{"ip4:0.0.0.0/24", "ip6:56:0::0:7"}
	expNFs := []string{"exists:somedomain.edu", "exp=exp.example.com"}
	for _, d := range []string{"mydomain", "abcd.net", "info.info", "example.com"} {
		for _, ip := range IP_LOOKUP[d] {
			expIPs = append(expIPs, writeIPMech(ip, ""))
		}
	}
	err := r.FlattenSPF(domain, spf)
	if err = r.compareExpected(err, " -all", expIPs, expNFs); err != nil {
		t.Fatal(err)
	}
}

func TestFlattenRedirects(t *testing.T) {
	r := RootSPF{MapIPs: map[string]bool{}, LookupIF: mockLookup{}}
	domain, spf := "somedomain", "v=spf1 ip4:9.9.9.9 redirect=mydomain ip6:2:2:2:2::::"
	// Test that mechanisms after redirects are ignored
	expIPs := []string{"ip4:9.9.9.9"}
	for _, ip := range IP_LOOKUP["mydomain"] {
		expIPs = append(expIPs, writeIPMech(ip, ""))
	}
	err := r.FlattenSPF(domain, spf)
	if err = r.compareExpected(err, "", expIPs, []string{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.MapIPs["ip6:2:2:2:2::::"]; ok {
		t.Fatal("Mechanisms after redirect should have been ignored")
	}
	// Test that redirects are ignored if SPF record includes `all` mechanism
	r.MapIPs = map[string]bool{}
	err = r.FlattenSPF(domain, spf+" ~all")
	if err = r.compareExpected(err, "", []string{"ip4:9.9.9.9"}, []string{}); err != nil {
		t.Fatal(err)
	}
	if len(r.MapIPs) > 2 {
		t.Fatal("Redirect should have been ignored since `all` mechanism in SPF record")
	}
}

func TestFlattenModifiers(t *testing.T) {
	// Test modifier logic
	r := RootSPF{MapIPs: map[string]bool{}, MapNonflat: map[string]bool{}, LookupIF: mockLookup{}}
	domain, spf := "somedomain", "v=spf1 -include:mydomain +ip4:9.8.7.6/54 ~exists:otherdomain ?mx:test.domain -all"
	r.RootDomain = domain
	expIPs := []string{"ip4:9.8.7.6/54"}
	for _, d := range MX_LOOKUP["test.domain"] {
		for _, ip := range IP_LOOKUP[d.Host] {
			expIPs = append(expIPs, writeIPMech(ip, ""))
		}
	}
	err := r.FlattenSPF(domain, spf)
	if err = r.compareExpected(err, " -all", expIPs, []string{}); err != nil {
		t.Fatal(err)
	}
	// Test IPs for `mydomain` are skipped because of fail modifier - on `include` mechanism
	for _, ip := range IP_LOOKUP["mydomain"] {
		if _, ok := r.MapIPs[writeIPMech(ip, "")]; ok {
			t.Fatal("IP should have been ignored because its include modifier was `-`")
		}
		expIPs = append(expIPs, "-"+writeIPMech(ip, ""))
	}
	// Test `exists` mechanism skipped because of its fail modifier ~
	if _, ok := r.MapNonflat["exists:otherdomain"]; ok {
		t.Fatal("`exists` should have been ignored because its modifier was `~`")
	}
}

// TESTS FOR GetDomainSPF() ===================================================================

func TestGetDomainSPF(t *testing.T) {
	r := RootSPF{LookupIF: mockLookup{}}
	// Check that correctly filters TXT records for SPF record
	record, _ := r.GetDomainSPFRecord("mydomain")
	if record != "v=spf1 a ~all" {
		t.Fatal("Filtering for SPF record failed.")
	}
	// Check that returns error when no SPF record found
	_, err := r.GetDomainSPFRecord("nospf")
	if !regexp.MustCompile("^no SPF record found for.*$").MatchString(err.Error()) {
		t.Fatal("Should have failed to find SPF record for `nospf`")
	}
}

// TESTS FOR CheckDomainSPF() =================================================================

func TestCheckDomainSPF(t *testing.T) {
	r := RootSPF{LookupIF: mockLookup{}}
	domain, record := "mydomain", "v=spf1 a ~all"
	// Check that SPF record matches expected whether or not provided in input
	for _, inputSPF := range []string{"", record} {
		checkedRecord, err := r.CheckSPFRecord(domain, inputSPF)
		if checkedRecord != record {
			t.Fatalf("SPF record lookup did not match expected. Expected `%s` but got `%s`", record, checkedRecord)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Check that returns error when SPF record does not match expected format
	_, err := r.CheckSPFRecord(domain, "spf1 a ~all")
	if !regexp.MustCompile("^.*did not match expected format.*$").MatchString(err.Error()) {
		t.Fatal("SPF record check should have failed")
	}
}

// TESTS FOR WriteFlatSPF() ===================================================================

func TestWriteFlatSPF(t *testing.T) {
	r := RootSPF{
		AllMechanism: " -all",
		MapIPs:       map[string]bool{"ip4:0.0.0.0": true, "ip6:1:1:1:1::::": true},
		MapNonflat:   map[string]bool{"exists:domain": true, "ptr": true, "exists:anotherdomain": true},
	}
	expectedSPF := "v=spf1 ip4:0.0.0.0 ip6:1:1:1:1:::: exists:domain ptr exists:anotherdomain -all"

	// Check that written SPF record starts with `v=sfp1` and ends with `all` mechanism
	outputSPF := r.WriteFlatSPF()
	if regexp.MustCompile("^(v=spf1).* (/-all)$").MatchString(outputSPF) {
		t.Fatalf("SFP record should start with 'v=sfp1' and end with `all` mechanism if set.\nGot: `%s`", outputSPF)
	}
	// Check that both SPF records have the same entries (order doesn't matter)
	if matched, inStart, inEnd := CompareRecords(expectedSPF, outputSPF); !matched {
		t.Fatalf("SPF record does not include expected entries. Should include `%s` and should not include `%s`", inStart, inEnd)
	}
}

// TESTS FOR CompareRecords() =================================================================

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
