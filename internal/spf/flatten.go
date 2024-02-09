// FLATTEN SPF RECORD =========================================================================
package spf

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
)

type Lookup interface {
	LookupTXT(string) ([]string, error)
	LookupIP(string) ([]net.IP, error)
	LookupMX(string) ([]*net.MX, error)
}

type NetLookup struct{}

func (n NetLookup) LookupTXT(s string) ([]string, error) {
	return net.LookupTXT(s)
}
func (n NetLookup) LookupIP(s string) ([]net.IP, error) {
	return net.LookupIP(s)
}
func (n NetLookup) LookupMX(s string) ([]*net.MX, error) {
	return net.LookupMX(s)
}

func writeIPMech(ip net.IP, prefix string) string {
	IPV := map[int]string{
		4:  "4",
		16: "6",
	}
	return "ip" + IPV[len(ip)] + ":" + ip.String() + prefix
}

type RootSPF struct {
	RootDomain   string
	AllMechanism string
	MapIPs       map[string]bool
	MapNonflat   map[string]bool
	LookupIF     Lookup
}

func NewRootSPF(rootDomain string, lookupIF Lookup) RootSPF {
	return RootSPF{RootDomain: rootDomain, LookupIF: lookupIF, MapIPs: map[string]bool{}, MapNonflat: map[string]bool{}}
}

// Check or lookup SPF record for domain, then parse each mechanism.
// This runs recursively until every mechanism is added either to
// r.AllMechanism, r.MapIPs, or r.MapNonflat (or ignored)
func (r *RootSPF) FlattenSPF(domain, spfRecord string) error {
	slog.Debug("--- Flattening domain ---", "domain", domain)
	spfRecord, err := CheckSPFRecord(domain, spfRecord, r.LookupIF)
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
		if err := r.ConvertDomainToIP(mx.Host, prefixLength); err != nil {
			return fmt.Errorf("could not lookup IPs for MX record `%s`: %s\n", mx.Host, err)
		}
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
