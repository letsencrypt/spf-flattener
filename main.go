package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// GLOBAL VARIALBES ===========================================================================

var VERBOSE bool
var ROOT_DOMAIN string
var ALL_MECHANISM string

// MAP_IPS records flattened IPv4 and IPv6 addresses
var MAP_IPS map[string]bool

// MAP_NONFLAT records SPF mechanisms that can't be flattened
var MAP_NONFLAT map[string]bool

// Make lookup functions abstract for testing purposes
var LOOKUP_TXT_FUNC func(string) ([]string, error)
var LOOKUP_IP_FUNC func(string) ([]net.IP, error)
var LOOKUP_MX_FUNC func(string) ([]*net.MX, error)

// Map length of net.IP object to IP address version
var IPV = map[int]string{
	4:  "4",
	16: "6",
}

// DEBUG ======================================================================================

// Print debug lines if VERBOSE true
func debug(format string, a ...any) {
	if VERBOSE {
		fmt.Printf(format, a...)
	}
}

// SPF FLATTENING FUNCTIONS ===================================================================

// Return the SPF record for the given domain
func getDomainSPFRecord(domain string) (string, error) {
	txtRecords, err := LOOKUP_TXT_FUNC(domain)
	if err != nil {
		return "", fmt.Errorf("could not look up SPF record for %s:\n %s", domain, err)
	}
	for _, record := range txtRecords {
		// TBD: check that only one SPF record exists for domain and fail otherwise?
		if regexp.MustCompile(`^v=spf1.*$`).MatchString(record) {
			debug("Found SPF record for %s: '%s'\n", domain, record)
			return record, nil
		}
	}
	return "", fmt.Errorf("no SPF record found for %s", domain)
}

// If provided SPF record is blank, lookup and return SPF record for domain
// Otherwise, check that given record matches expected format and return that
func checkSPFRecord(domain, spfRecord string) (string, error) {
	if spfRecord == "" {
		record, err := getDomainSPFRecord(domain)
		if err != nil {
			return "", fmt.Errorf("could not get SPF record for %s:\n %s", domain, err)
		}
		return record, nil
	}
	spfRecord = strings.ReplaceAll(spfRecord, "\n", " ")
	if regexp.MustCompile(`^v=spf1.*$`).MatchString(spfRecord) {
		return spfRecord, nil
	}
	return "", fmt.Errorf("SPF record for %s did not match expected format. Got '%s'", domain, spfRecord)
}

// Check or lookup SPF record for domain, then parse each mechanism.
// This runs recursively until every mechanism is added either to
// ALL_MECHANISM, MAP_IPS, or MAP_NONFLAT
func flattenSPF(domain, spfRecord string) error {
	debug("--- Flattening: %s\n", domain)
	spfRecord, err := checkSPFRecord(domain, spfRecord)
	if err != nil {
		return fmt.Errorf("invalid SPF record for %s:\n %s", domain, err)
	}
	containsAll := regexp.MustCompile(`^.* (\+|-|~|\?)?all$`).MatchString(spfRecord)
	for _, mechanism := range strings.Split(spfRecord, " ")[1:] {
		// TODO: modifiers (+-~?) for mechanisms other than all
		// Handle by passing modifier into flattened record or by only evaluating mechanism if +,? or no modifier?
		isRedirect, err := parseMechanism(strings.TrimSpace(mechanism), domain, containsAll)
		if err != nil {
			return fmt.Errorf("could not flatten SPF record for %s:\n %s", domain, err)
		}
		if isRedirect {
			break
		}
	}
	return nil
}

// Parse the given mechanism and dispatch it accordingly
func parseMechanism(mechanism, domain string, containsAll bool) (bool, error) {
	switch {
	// Copy `all` mechanism if set by ROOT_DOMAIN
	case regexp.MustCompile(`^(\+|-|~|\?)?all`).MatchString(mechanism):
		if domain == ROOT_DOMAIN {
			debug("Setting `all` mechanism to `%s`\n", mechanism)
			ALL_MECHANISM = " " + mechanism
		}
	// Add IPv4 and IPv6 addresses to MAP_IPS
	case regexp.MustCompile(`^ip(4|6):.*$`).MatchString(mechanism):
		debug("Adding '%s' mechanism\n", mechanism)
		MAP_IPS[mechanism] = true
	// Convert A/AAAA and MX records, then add to MAP_IPS
	case regexp.MustCompile(`^a$`).MatchString(mechanism): // a
		return false, convertDomainToIP(domain, "")
	case regexp.MustCompile(`^a/(\d){1,3}`).MatchString(mechanism): // a/<prefix-length>
		return false, convertDomainToIP(domain, mechanism[strings.Index(mechanism, "/"):])
	case regexp.MustCompile(`^a:.*/(\d){1,3}$`).MatchString(mechanism): // a:domain/<prefix-length>
		return false, convertDomainToIP(mechanism[strings.Index(mechanism, ":")+1:strings.LastIndex(mechanism, "/")], mechanism[strings.LastIndex(mechanism, "/"):])
	case regexp.MustCompile(`^a:.*$`).MatchString(mechanism): // a:domain
		return false, convertDomainToIP(strings.SplitN(mechanism, ":", 2)[1], "")
	case regexp.MustCompile(`^mx$`).MatchString(mechanism): // mx
		return false, convertMxToIP(domain, "")
	case regexp.MustCompile(`^mx/(\d){1,3}`).MatchString(mechanism): // mx/<prefix-length>
		return false, convertMxToIP(domain, mechanism[strings.Index(mechanism, "/"):])
	case regexp.MustCompile(`^mx:.*/(\d){1,3}$`).MatchString(mechanism): // mx:domain/<prefix-length>
		return false, convertMxToIP(mechanism[strings.Index(mechanism, ":")+1:strings.LastIndex(mechanism, "/")], mechanism[strings.LastIndex(mechanism, "/"):])
	case regexp.MustCompile(`mx:.*$`).MatchString(mechanism): // mx:domain
		return false, convertMxToIP(strings.SplitN(mechanism, ":", 2)[1], "")
	// Add ptr, exists, and exp mechanisms to MAP_NONFLAT
	case regexp.MustCompile(`^ptr$`).MatchString(mechanism):
		debug("Adding `%s` mechanism\n", mechanism)
		MAP_NONFLAT[mechanism+":"+domain] = true
	case regexp.MustCompile(`^(ptr:|exists:|exp=).*$`).MatchString(mechanism):
		debug("Adding `%s` mechanism\n", mechanism)
		MAP_NONFLAT[mechanism] = true
	// Recursive call to flattenSPF on `include` mechanism
	case regexp.MustCompile(`^include:.*$`).MatchString(mechanism):
		return false, flattenSPF(strings.SplitN(mechanism, ":", 2)[1], "")
	// Recursive call to flattenSPF on `redirect` mechanism, but handle extra logic processing:
	// 1) ignore `redirect` if SPF record includes an `all` mechanism, and
	// 2) ignore all following mechanisms in the SPF record after `redirect`.
	case regexp.MustCompile(`^redirect=.*$`).MatchString(mechanism):
		if containsAll {
			debug("Skipping `redirect` modifier `%s` because SPF record contains `all` mechanism\n", mechanism)
			return true, nil
		}
		return true, flattenSPF(strings.SplitN(mechanism, "=", 2)[1], "")
	// Return error if no match
	default:
		return false, fmt.Errorf("received unexpected SPF mechanism or syntax: '%s'", mechanism)
	}
	return false, nil
}

// Convert A/AAAA records to IPs and add them to MAP_IPS
func convertDomainToIP(domain, prefixLength string) error {
	debug("Looking up IP records for %s\n", domain)
	ips, err := LOOKUP_IP_FUNC(domain)
	if err != nil {
		return fmt.Errorf("could not lookup IPs for %s:\n %s", domain, err)
	}
	for _, ip := range ips {
		debug("A/AAAA record found for %s: '%s'\n", domain, ip.String())
		if _, ok := IPV[len(ip)]; !ok {
			return fmt.Errorf("could not parse IP address '%s' for %s", ip.String(), domain)
		}
		MAP_IPS["ip"+IPV[len(ip)]+":"+ip.String()+prefixLength] = true
	}
	return nil
}

// Convert MX records to domains then to IPs and add them to MAP_IPS
func convertMxToIP(domain, prefixLength string) error {
	debug("Looking up MX records for %s\n", domain)
	mxs, err := LOOKUP_MX_FUNC(domain)
	if err != nil {
		return fmt.Errorf("could not lookup MX records for %s:\n %s", domain, err)
	}
	for _, mx := range mxs {
		debug("Found MX record for %s: '%s'\n", domain, mx.Host)
		convertDomainToIP(mx.Host, prefixLength)
	}
	return nil
}

// Flatten and write new SPF record for root domain by compiling ALL_MECHANISM, MAP_IPs, and MAP_NONFLAT
func writeFlatSPF() string {
	flatSPF := "v=spf1"
	for ip := range MAP_IPS {
		flatSPF += " " + ip
	}
	for nonflat := range MAP_NONFLAT {
		flatSPF += " " + nonflat
	}
	flatSPF += ALL_MECHANISM
	return flatSPF
}

// INPUT/OUTPUT PROCESSING ====================================================================

// Parse, check, and return flag inputs
func parseFlags() (initialSPF string, dryrun bool, warn bool, url string, authEmail string, authKey string, err error) {
	rootDomain := flag.String("domain", "", "Initial domain to set SPF record for") // required
	ogRecord := flag.String("initialSPF", "", "Initial SPF record to flatten")      // optional
	verboseF := flag.Bool("verbose", false, "")                                     // optional
	dryrunF := flag.Bool("dryrun", true, "")                                        // optional
	warnF := flag.Bool("warn", true, "")                                            // optional TODO: come up with better name
	urlF := flag.String("url", "", "API URL for SPF record")                        // optional unless dryrun is false
	authEmailF := flag.String("authEmail", "", "API key for X-Auth-Email header")   // optional unless dryrun is false
	authKeyF := flag.String("authKey", "", "API key for X-Auth-Key header")         // optional unless dryrun is false
	// TBD: possible flags to add in the future: list of mechanisms to ignore or fail on, timeout/max recursions
	flag.Parse()

	// Require domain to be nonempty
	if *rootDomain == "" {
		err = fmt.Errorf("must provide a domain to flatten SPF record for. Use '-domain <yourdomain>'")
		return
	}
	ROOT_DOMAIN = *rootDomain
	VERBOSE = *verboseF
	fmt.Println("HERE: ", *ogRecord)
	// Check SPF record provided (or look up existing record if empty)
	initialSPF, err = checkSPFRecord(ROOT_DOMAIN, *ogRecord)
	if err != nil {
		err = fmt.Errorf("problem with initial SPF record: %s)", err)
		return
	}
	fmt.Println("THERE: ", initialSPF)

	// Require url, authEmail, and authKey to be nonempty if dryrun is false
	if !*dryrunF && (*urlF == "" || *authEmailF == "" || *authKeyF == "") {
		err = fmt.Errorf("'url', 'authEmail', and 'authKey' flags cannot be blank if 'dryrun' set to false")
		return
	}

	debug("Setting flags: rootDomain='%s', initialSPF='%s',\n", ROOT_DOMAIN, initialSPF)
	debug("\tverbose=%v, dryrun=%v, warn=%v,\n", VERBOSE, *dryrunF, *warnF)
	debug("\turl='%s', authEmail='%s', authKey='%s'\n", *urlF, *authEmailF, *authKeyF)
	return initialSPF, *dryrunF, *warnF, *urlF, *authEmailF, *authKeyF, nil
}

// Compare intial and flattened SPF records by checking that they both
// have the same entries regardless of order. Return any different entries.
func compareRecords(startSPF, endSPF string) (bool, string, string) {
	startList, endList := strings.Split(startSPF, " "), strings.Split(endSPF, " ")
	sort.Strings(startList)
	sort.Strings(endList)
	inStart, inEnd := "", ""
	i, j := 0, 0
	for i < len(startList) || j < (len(endList)) {
		switch {
		case (j == len(endList) && i < len(endList)) || (i < len(startList) && j < len(endList) && startList[i] < endList[j]):
			inStart += " " + startList[i]
			i++
		case (i == len(startList) && j < len(endList)) || (i < len(startList) && j < len(endList) && startList[i] > endList[j]):
			inEnd += " " + endList[j]
			j++
		default: // startList[i] == endList[j]
			i++
			j++
		}
	}
	if len(inStart) == 0 && len(inEnd) == 0 {
		return true, "", ""
	}
	return false, strings.TrimSpace(inStart), strings.TrimSpace(inEnd)
}

// PATCH the updated, flattened SPF record
func updateSPFRecord(flatSPF, url, authEmail, authKey string) error {
	payloadString := fmt.Sprintf("{\n  \"content\": \"%s\",\n  \"name\": \"%s\",\n  \"type\": \"TXT\",\n  \"comment\": \"Dynamically updated, flattened SPF record\"}", flatSPF, ROOT_DOMAIN)
	payload := strings.NewReader(payloadString)

	req, err := http.NewRequest("PATCH", url, payload)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Auth-Email", authEmail)
	req.Header.Add("X-Auth-Key", authKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("failed to update SPF record. Got response: `%d` -- `%s`", res.StatusCode, res.Body)
	}
	return nil
}

// MAIN =======================================================================================

func main() {
	LOOKUP_TXT_FUNC, LOOKUP_IP_FUNC, LOOKUP_MX_FUNC = net.LookupTXT, net.LookupIP, net.LookupMX

	// Parse input
	initialSPF, dryrun, warn, url, authEmail, authKey, err := parseFlags()
	if err != nil {
		log.Fatalf("Could not parse flags: %s", err)
	}

	/// Do the stuff
	MAP_IPS, MAP_NONFLAT = make(map[string]bool), make(map[string]bool)
	if err = flattenSPF(ROOT_DOMAIN, initialSPF); err != nil {
		log.Fatalf("Could not flatten SPF for initial domain:\n %s", err)
		return
	}
	flatSPF := writeFlatSPF()

	// Output flattened SPF record
	debug("\n####=========== Flattened SPF for %s ===========####\n", ROOT_DOMAIN)
	fmt.Println(flatSPF) // TODO: decide best way to output flattened SPF and warnings/comparisons

	if warn {
		same, inInitial, inFlat := compareRecords(initialSPF, flatSPF)
		if same {
			fmt.Println("SPF record is unchanged")
			return
		}
		fmt.Printf("Flattened SPF record differs from initial SPF record. Differences:\n\t- %s\n\t+ %s\n", inInitial, inFlat)
	}
	if dryrun {
		return
	}

	// Export flattened SPF record
	if err = updateSPFRecord(flatSPF, url, authEmail, authKey); err != nil {
		log.Fatalf("Could not export updated SPF record:\n %s", err)
	}
	fmt.Println("Successfully updated SPF record!")
}

// TBD: at what point should this tool be broken up into multiple files
