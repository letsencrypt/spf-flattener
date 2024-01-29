package spf

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

type RootSPF struct {
	RootDomain   string
	AllMechanism string
	MapIPs       map[string]bool
	MapNonflat   map[string]bool
	LookupIF     Lookup
}

type Lookup interface {
	LookupTXT(string) ([]string, error)
	LookupIP(string) ([]net.IP, error)
	LookupMX(string) ([]*net.MX, error)
}

func writeIPMech(ip net.IP, prefix string) string {
	IPV := map[int]string{
		4:  "4",
		16: "6",
	}
	return "ip" + IPV[len(ip)] + ":" + ip.String() + prefix
}

// SPF FLATTENING FUNCTIONS ===================================================================

// Return the SPF record for the given domain
func (r *RootSPF) GetDomainSPFRecord(domain string) (string, error) {
	txtRecords, err := r.LookupIF.LookupTXT(domain)
	if err != nil {
		return "", fmt.Errorf("could not look up SPF record for %s:\n %s", domain, err)
	}
	for _, record := range txtRecords {
		// TBD: check that only one SPF record lookupexists for domain and fail otherwise?
		if regexp.MustCompile(`^v=spf1.*$`).MatchString(record) {
			slog.Debug("Found SPF record", "domain", domain, "spf_record", record)
			return record, nil
		}
	}
	return "", fmt.Errorf("no SPF record found for %s", domain)
}

// If provided SPF record is blank, lookup and return SPF record for domain
// Otherwise, check that given record matches expected format and return that
func (r *RootSPF) CheckSPFRecord(domain, spfRecord string) (string, error) {
	if spfRecord == "" {
		record, err := r.GetDomainSPFRecord(domain)
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
// r.AllMechanism, r.MapIPs, or r.MapNonflat (or ignored)
func (r *RootSPF) FlattenSPF(domain, spfRecord string) error {
	slog.Debug("--- Flattening domain ---", "domain", domain)
	spfRecord, err := r.CheckSPFRecord(domain, spfRecord)
	if err != nil {
		return fmt.Errorf("invalid SPF record for %s:\n %s", domain, err)
	}
	containsAll := regexp.MustCompile(`^.* (\+|-|~|\?)?all$`).MatchString(spfRecord)
	for _, mechanism := range strings.Split(spfRecord, " ")[1:] {
		// If not `all`, skip mechanism if fail modifier (- or ~) and ignore modifier otherwise
		if regexp.MustCompile(`^(\+|-|~|\?)$`).MatchString(mechanism[:1]) && !regexp.MustCompile(`^all$`).MatchString(mechanism[1:]) {
			if regexp.MustCompile(`^(-|~)$`).MatchString(mechanism[:1]) {
				continue
			}
			mechanism = mechanism[1:]
		}
		// Skip `redirect` if SPF record includes an `all` mechanism
		isRedirect := regexp.MustCompile(`^redirect=.*$`).MatchString(mechanism)
		if isRedirect && containsAll {
			continue
		}
		// Parse mechanism
		err := r.ParseMechanism(strings.TrimSpace(mechanism), domain)
		if err != nil {
			return fmt.Errorf("could not flatten SPF record for %s:\n %s", domain, err)
		}
		// Skip all mechanisms after `redirect`
		if isRedirect {
			break
		}
	}
	return nil
}

// Parse the given mechanism and dispatch it accordingly
func (r *RootSPF) ParseMechanism(mechanism, domain string) error {
	lastSlashIndex := strings.LastIndex(mechanism, "/")
	switch {
	// Copy `all` mechanism if set by ROOT_DOMAIN
	case regexp.MustCompile(`^(\+|-|~|\?)?all`).MatchString(mechanism):
		if domain == r.RootDomain {
			slog.Debug("Setting `all` mechanism", "mechanism", mechanism)
			r.AllMechanism = " " + mechanism
		}
	// Add IPv4 and IPv6 addresses to r.MapIPs
	case regexp.MustCompile(`^ip(4|6):.*$`).MatchString(mechanism):
		slog.Debug("Adding IP mechanism", "mechanism", mechanism)
		r.MapIPs[mechanism] = true
	// Convert A/AAAA and MX records, then add to r.MapIPs
	case regexp.MustCompile(`^a$`).MatchString(mechanism): // a
		return r.ConvertDomainToIP(domain, "")
	case regexp.MustCompile(`^a/\d{1,3}`).MatchString(mechanism): // a/<prefix-length>
		return r.ConvertDomainToIP(domain, mechanism[1:])
	case regexp.MustCompile(`^a:.*/\d{1,3}$`).MatchString(mechanism): // a:<domain>/<prefix-length>
		return r.ConvertDomainToIP(mechanism[strings.Index(mechanism, ":")+1:lastSlashIndex], mechanism[lastSlashIndex:])
	case regexp.MustCompile(`^a:.*$`).MatchString(mechanism): // a:<domain>
		return r.ConvertDomainToIP(strings.SplitN(mechanism, ":", 2)[1], "")
	case regexp.MustCompile(`^mx$`).MatchString(mechanism): // mx
		return r.ConvertMxToIP(domain, "")
	case regexp.MustCompile(`^mx/\d{1,3}`).MatchString(mechanism): // mx/<prefix-length>
		return r.ConvertMxToIP(domain, mechanism[2:])
	case regexp.MustCompile(`^mx:.*/\d{1,3}$`).MatchString(mechanism): // mx:<domain>/<prefix-length>
		return r.ConvertMxToIP(mechanism[strings.Index(mechanism, ":")+1:lastSlashIndex], mechanism[lastSlashIndex:])
	case regexp.MustCompile(`mx:.*$`).MatchString(mechanism): // mx:<domain>
		return r.ConvertMxToIP(strings.SplitN(mechanism, ":", 2)[1], "")
	// Add ptr, exists, and exp mechanisms to r.MapNonflat
	case regexp.MustCompile(`^ptr$`).MatchString(mechanism):
		slog.Debug("Adding nonflat mechanism", "mechanism", mechanism+":"+domain)
		r.MapNonflat[mechanism+":"+domain] = true
	case regexp.MustCompile(`^(ptr:|exists:|exp=).*$`).MatchString(mechanism):
		slog.Debug("Adding nonflat mechanism", "mechanism", mechanism)
		r.MapNonflat[mechanism] = true
	// Recursive call to FlattenSPF on `include` and `redirect` mechanism
	case regexp.MustCompile(`^(include:|redirect=).*$`).MatchString(mechanism):
		return r.FlattenSPF(mechanism[strings.IndexAny(mechanism, ":=")+1:], "")
	// Return error if no match
	default:
		return fmt.Errorf("received unexpected SPF mechanism or syntax: '%s'", mechanism)
	}
	return nil
}

// Convert A/AAAA records to IPs and add them to r.MapIPs
func (r *RootSPF) ConvertDomainToIP(domain, prefixLength string) error {
	slog.Debug("Looking up IP records for domain", "domain", domain)
	ips, err := r.LookupIF.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("could not lookup IPs for %s:\n %s", domain, err)
	}
	for _, ip := range ips {
		slog.Debug("Adding IP mechanism", "mechanism", writeIPMech(ip, prefixLength))
		r.MapIPs[writeIPMech(ip, prefixLength)] = true
	}
	return nil
}

// Convert MX records to domains then to IPs and add them to r.MapIPs
func (r *RootSPF) ConvertMxToIP(domain, prefixLength string) error {
	slog.Debug("Looking up MX records for domain", "domain", domain)
	mxs, err := r.LookupIF.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("could not lookup MX records for %s:\n %s", domain, err)
	}
	for _, mx := range mxs {
		slog.Debug("Found MX record for domain", "mx_record", mx.Host)
		r.ConvertDomainToIP(mx.Host, prefixLength)
	}
	return nil
}

// Flatten and write new SPF record for root domain by compiling r.AllMechanism, r.MapIPs, and r.MapNonflat
func (r *RootSPF) WriteFlatSPF() string {
	flatSPF := "v=spf1"
	for ip := range r.MapIPs {
		flatSPF += " " + ip
	}
	for nonflat := range r.MapNonflat {
		flatSPF += " " + nonflat
	}
	flatSPF += r.AllMechanism
	return flatSPF
}

// OUTPUT PROCESSING FUNCTIONS ================================================================

// Compare intial and flattened SPF records by checking that they both
// have the same entries regardless of order. Return any different entries.
func CompareRecords(startSPF, endSPF string) (bool, string, string) {
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

type PatchRequest struct {
	Content string `json:"content"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
}

// PATCH the updated, flattened SPF record
func UpdateSPFRecord(rootDomain, flatSPF, url, authEmail, authKey string) error {
	// {\n  \"content\": \"<SPF_RECORD>\",\n  \"name\": \"<DOMAIN>\",\n  \"type\": \"TXT\",\n  \"comment\": \"Dynamically updated, flattened SPF record\"}
	patchReq := PatchRequest{
		Content: flatSPF,
		Name:    rootDomain,
		Type:    "TXT",
		Comment: "Dynamically updated, flattened SPF record",
	}
	payload, err := json.MarshalIndent(patchReq, "", "  ")
	if err != nil {
		return err
	}
	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(payload)))
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
