package spf

import (
	"fmt"
	"net"
	"regexp"
	"testing"
)

type mockLookup struct{}

func (n mockLookup) LookupTXT(s string) ([]string, error) {
	return txtLookup[s], nil
}
func (n mockLookup) LookupIP(s string) ([]net.IP, error) {
	return ipLookup[s], nil
}
func (n mockLookup) LookupMX(s string) ([]*net.MX, error) {
	return mxLookup[s], nil
}

var txtLookup = map[string][]string{
	"mydomain":    {"NOT AN SPF RECORD", "v=spf1 a ~all"},
	"test.com":    {"v=spf1 ip4:10.10.10.10", "exp='IDK why that failed, good luck'"},
	"example.com": {"v=spf1 include:mydomain exp=exp.example.com"},
	"nospf":       {"NOT AN SPF RECORD", "v=also not an spf record"},
}

var ipLookup = map[string][]net.IP{
	"mydomain":                               {net.IP{0, 0, 0, 0}, net.IP{1, 2, 3, 4}},
	"example.com":                            {net.ParseIP("2001:db8::68")},
	"abcd.net":                               {net.IP{12, 34, 56, 78}, net.ParseIP("2001:db8::1"), net.IP{6, 6, 6, 6}},
	"info.info":                              {net.IP{1, 1, 1, 1}, net.IP{2, 2, 2, 2}, net.IP{3, 3, 3, 3}, net.ParseIP("1:2:3:4:5:6:7:8")},
	"longer.domain/subdomain/subsubdomain/a": {net.ParseIP("1234:34::1")},
}
var mxLookup = map[string][]*net.MX{
	"anotherdomain": {&net.MX{Host: "mydomain", Pref: 10}},
	"test.org":      {&net.MX{Host: "example.com", Pref: 20}, &net.MX{Host: "abcd.net", Pref: 10}},
	"test.domain":   {&net.MX{Host: "example.com", Pref: 10}, &net.MX{Host: "info.info", Pref: 30}},
}

// Check if input error is nil, if r.ALlMechanism is expected, and if r.MapIPs and r.MapNonflat have the expected entries.
func (r *RootSPF) compareExpected(err error, expAll string, expIPs, expNF []string) error {
	if err != nil {
		return fmt.Errorf("unexpected error: %s\n", err)
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

func TestParseMechanismAll(t *testing.T) {
	r := NewRootSPF("myrootdomain", mockLookup{}, "")
	// Test `all`` mechanism set if domain is root
	err := r.ParseMechanism("~all", "myrootdomain", r.TraceTree.Root())
	if err = r.compareExpected(err, " ~all", []string{}, []string{}); err != nil {
		t.Fatal(err)
	}
	// Test `all`` mechanism is ignored if domain is NOT root
	err = r.ParseMechanism("-all", "NOTmyrootdomain", r.TraceTree.Root())
	if err = r.compareExpected(err, " ~all", []string{}, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismIP(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
	// Test ip mechanisms of the form `ip4:<ipaddr>`, `ip4:<ipaddr>/<prefix-length>, `ip6:<ipaddr>`, and `ip6:<ipaddr>/<prefix-length>`
	ipMechs := []string{"ip4:abcd", "ip4:8.8.8.8", "ip6:efgh/36", "ip6:2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ip6:11:22::33/128"}
	for _, mech := range ipMechs {
		err := r.ParseMechanism(mech, "", r.TraceTree.Root())
		if err = r.compareExpected(err, "", []string{mech}, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismA(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
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
		for _, ip := range ipLookup[testCase[2]] {
			expIPs = append(expIPs, writeIPMech(ip, testCase[1]))
		}
		err := r.ParseMechanism(testCase[0], testCase[3], r.TraceTree.Root())
		if err = r.compareExpected(err, "", expIPs, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismMX(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
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
		for _, d := range mxLookup[testCase[2]] {
			for _, ip := range ipLookup[d.Host] {
				expIPs = append(expIPs, writeIPMech(ip, testCase[1]))
			}
		}
		err := r.ParseMechanism(testCase[0], testCase[3], r.TraceTree.Root())
		if err = r.compareExpected(err, "", expIPs, []string{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismNonFlat(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
	// Test ptr mechanism of the form `ptr`
	err := r.ParseMechanism("ptr", "domain", r.TraceTree.Root())
	if err = r.compareExpected(err, "", []string{}, []string{"ptr:domain"}); err != nil {
		t.Fatal(err)
	}
	// Test nonflat mechanisms of the form `ptr:<domain>`, `<exists:<domain>`, and `exp=<domain>`
	nfMechs := []string{"ptr:example.com", "exists:yourdomain", "exp=explain.example.com"}
	for _, nfMech := range nfMechs {
		err := r.ParseMechanism(nfMech, "", r.TraceTree.Root())
		if err = r.compareExpected(err, "", []string{}, []string{nfMech}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseMechanismInclude(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
	// Test mechanism of the form `include:<domain>`
	includeDomain := "mydomain" // SPF record is just `a`, so expect IPs for "mydomain"
	expIPs := []string{}
	for _, ip := range ipLookup[includeDomain] {
		expIPs = append(expIPs, writeIPMech(ip, ""))
	}
	err := r.ParseMechanism("include:"+includeDomain, "notmydomain", r.TraceTree.Root())
	if err = r.compareExpected(err, "", expIPs, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismRedirect(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
	// Test mechanism of the form `redirect=<domain>`
	redirectDomain := "test.com" // SPF record is just ip4:10.10.10.10
	err := r.ParseMechanism("redirect="+redirectDomain, "notmydomain", r.TraceTree.Root())
	if err = r.compareExpected(err, "", []string{"ip4:10.10.10.10"}, []string{}); err != nil {
		t.Fatal(err)
	}
}

func TestParseMechanismFails(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
	// Test that parseMechanism fails on unexpected mechanism or syntax error
	noMatchRegex := regexp.MustCompile(`^received unexpected SPF mechanism or syntax.*$`)
	for _, wrongMech := range []string{"redirect:domain", "include=anotherdomain", "ip:0.0.0.0", "1.1.1.1", "", "ip6", "exp:explanation", "notMechanism:hello"} {
		err := r.ParseMechanism(wrongMech, "", r.TraceTree.Root())
		if !noMatchRegex.MatchString(err.Error()) {
			t.Fatalf("Expected `received unexpected SPF mechanism or syntax` error, got `%s` instead", err)
		}
	}
}

func TestFlattenSPF(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
	// Test that SPF record with multiple different entries gets flattened as expected
	domain, spf := "abcd.net", "v=spf1 ip4:0.0.0.0/24 include:example.com ip6:56:0::0:7 a mx:test.domain exists:somedomain.edu -all"
	// include:example.com --> (mydomain spf --> a --> mydomain IPs) + exp=exp.example.com
	// a --> abcd.net IPs
	// mx:test.domain --> example.com IPs and info.info IPs
	r.RootDomain = domain
	expIPs := []string{"ip4:0.0.0.0/24", "ip6:56:0::0:7"}
	expNFs := []string{"exists:somedomain.edu", "exp=exp.example.com"}
	for _, d := range []string{"mydomain", "abcd.net", "info.info", "example.com"} {
		for _, ip := range ipLookup[d] {
			expIPs = append(expIPs, writeIPMech(ip, ""))
		}
	}
	err := r.FlattenSPF(domain, spf, r.TraceTree.Root())
	if err = r.compareExpected(err, " -all", expIPs, expNFs); err != nil {
		t.Fatal(err)
	}
}

func TestNoFlattenKeeps(t *testing.T) {
	// Test that non-keep mechanisms get flattened
	r := NewRootSPF("", mockLookup{}, "include:example.com")
	domain, spf := "abcd.net", "v=spf1 ip4:8.8.8.8/24 include:example.com ip6:56:0::0:7 a mx:test.domain exists:somedomain.edu -all"
	r.RootDomain = domain
	expIPs := []string{"ip4:8.8.8.8/24", "ip6:56:0::0:7"}
	expNFs := []string{"exists:somedomain.edu", "include:example.com"}
	for _, d := range []string{"abcd.net", "info.info"} {
		for _, ip := range ipLookup[d] {
			expIPs = append(expIPs, writeIPMech(ip, ""))
		}
	}
	err := r.FlattenSPF(domain, spf, r.TraceTree.Root())
	r.UnflattenKeeps()
	if err = r.compareExpected(err, " -all", expIPs, expNFs); err != nil {
		t.Fatal(err)
	}
	// Test that keep mechanism "include:example.com" not flattened
	for _, ip := range ipLookup["mydomain"] {
		if _, ok := r.MapIPs[writeIPMech(ip, "")]; ok {
			t.Fatal("keep mechanism 'include:example.com' should not have been flattened")
		}
	}
	if _, ok := r.MapNonflat["exp=exp.example.com"]; ok {
		t.Fatal("keep mechanism 'include:example.com' should not have been flattened")
	}
}

func TestFlattenRedirects(t *testing.T) {
	r := NewRootSPF("", mockLookup{}, "")
	domain, spf := "somedomain", "v=spf1 ip4:9.9.9.9 redirect=mydomain ip6:2:2:2:2::::"
	// Test that mechanisms after redirects are ignored
	expIPs := []string{"ip4:9.9.9.9"}
	for _, ip := range ipLookup["mydomain"] {
		expIPs = append(expIPs, writeIPMech(ip, ""))
	}
	err := r.FlattenSPF(domain, spf, r.TraceTree.Root())
	if err = r.compareExpected(err, "", expIPs, []string{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.MapIPs["ip6:2:2:2:2::::"]; ok {
		t.Fatal("Mechanisms after redirect should have been ignored")
	}
	// Test that redirects are ignored if SPF record includes `all` mechanism
	r.MapIPs = map[string]bool{}
	err = r.FlattenSPF(domain, spf+" ~all", r.TraceTree.Root())
	if err = r.compareExpected(err, "", []string{"ip4:9.9.9.9"}, []string{}); err != nil {
		t.Fatal(err)
	}
	if len(r.MapIPs) > 2 {
		t.Fatal("Redirect should have been ignored since `all` mechanism in SPF record")
	}
}

func TestFlattenModifiers(t *testing.T) {
	// Test modifier logic
	r := NewRootSPF("", mockLookup{}, "")
	domain, spf := "somedomain", "v=spf1 -include:mydomain +ip4:9.8.7.6/54 ~exists:otherdomain ?mx:test.domain -all"
	r.RootDomain = domain
	expIPs := []string{"ip4:9.8.7.6/54"}
	for _, d := range mxLookup["test.domain"] {
		for _, ip := range ipLookup[d.Host] {
			expIPs = append(expIPs, writeIPMech(ip, ""))
		}
	}
	err := r.FlattenSPF(domain, spf, r.TraceTree.Root())
	if err = r.compareExpected(err, " -all", expIPs, []string{}); err != nil {
		t.Fatal(err)
	}
	// Test IPs for `mydomain` are skipped because of fail modifier - on `include` mechanism
	for _, ip := range ipLookup["mydomain"] {
		if _, ok := r.MapIPs[writeIPMech(ip, "")]; ok {
			t.Fatal("IP should have been ignored because its include modifier was `-`")
		}
	}
	// Test `exists` mechanism skipped because of its fail modifier ~
	if _, ok := r.MapNonflat["exists:otherdomain"]; ok {
		t.Fatal("`exists` should have been ignored because its modifier was `~`")
	}
}

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
