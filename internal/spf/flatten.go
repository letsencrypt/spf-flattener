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
	Keeps        string
	MapIPs       map[string]bool
	MapNonflat   map[string]bool
	LookupIF     Lookup
	LookupCount  int
	TraceTree    Tree
}

func NewRootSPF(rootDomain string, lookupIF Lookup, keep string) RootSPF {
	return RootSPF{RootDomain: rootDomain, Keeps: keep, MapIPs: map[string]bool{}, MapNonflat: map[string]bool{},
		LookupIF: lookupIF, LookupCount: 0, TraceTree: Tree{root: &node{name: rootDomain}}}

}

var allInRecordRegex = regexp.MustCompile(`^.* (\+|-|~|\?)?all$`)
var modifierRegex = regexp.MustCompile(`^(\+|-|~|\?)$`)

// Lookup or check SPF record for domain, then parse each mechanism.
// This runs recursively until every mechanism is added either to
// r.AllMechanism, r.MapIPs, or r.MapNonflat (or ignored)
func (r *RootSPF) FlattenSPF(domain, spfRecord string, parent Node) error {
	slog.Debug("--- Flattening domain ---", "domain", domain)
	if spfRecord == "" {
		record, err := GetDomainSPFRecord(domain, r.LookupIF)
		if err != nil {
			return fmt.Errorf("could not get SPF record for %s: %s\n", domain, err)
		}
		spfRecord = record
	} else {
		spfRecord = strings.ReplaceAll(spfRecord, "\n", " ")
		if err := CheckSPFRecord(domain, spfRecord, r.LookupIF); err != nil {
			return fmt.Errorf("invalid SPF record for %s: %s\n", domain, err)
		}
	}
	containsAll := allInRecordRegex.MatchString(spfRecord)
	for _, mechanism := range strings.Fields(spfRecord)[1:] {
		// If not `all`, skip mechanism if fail modifier (- or ~) and ignore modifier otherwise
		if modifierRegex.MatchString(mechanism[:1]) && !allRegex.MatchString(mechanism) {
			if mechanism[:1] == "-" || mechanism[:1] == "~" {
				continue
			}
			mechanism = mechanism[1:]
		}
		// Skip `redirect` if SPF record includes an `all` mechanism
		isRedirect := strings.HasPrefix(mechanism, "redirect=")
		if isRedirect && containsAll {
			continue
		}
		// Parse mechanism
		err := r.ParseMechanism(strings.TrimSpace(mechanism), domain, parent)
		if err != nil {
			return fmt.Errorf("could not flatten SPF record for %s: %s\n", domain, err)
		}
		// Skip all mechanisms after `redirect`
		if isRedirect {
			break
		}
	}
	return nil
}

var allRegex = regexp.MustCompile(`^(\+|-|~|\?)?all`)
var ipRegex = regexp.MustCompile(`^ip(4|6):.*$`)
var aPrefixRegex = regexp.MustCompile(`^a/\d{1,3}`)
var aDomainRegex = regexp.MustCompile(`^a:.*$`)
var aDomainPrefixRegex = regexp.MustCompile(`^a:.*/\d{1,3}$`)
var mxPrefixRegex = regexp.MustCompile(`^mx/\d{1,3}`)
var mxDomainRegex = regexp.MustCompile(`mx:.*$`)
var mxDomainPrefixRegex = regexp.MustCompile(`^mx:.*/\d{1,3}$`)
var nonflatRegex = regexp.MustCompile(`^(ptr:|exists:|exp=).*$`)
var includeOrRedirectRegex = regexp.MustCompile(`^(include:|redirect=).*$`)

// Parse the given mechanism and dispatch it accordingly
func (r *RootSPF) ParseMechanism(mechanism, domain string, parent Node) error {
	lastSlashIndex := strings.LastIndex(mechanism, "/")
	childNode := &node{name: mechanism, parent: parent}
	parent.AddChild(childNode)
	switch {
	// Copy `all` mechanism if set by ROOT_DOMAIN
	case allRegex.MatchString(mechanism):
		if domain == r.RootDomain {
			slog.Debug("Setting `all` mechanism", "mechanism", mechanism)
			r.AllMechanism = " " + mechanism
		}
	// Add IPv4 and IPv6 addresses to r.MapIPs
	case ipRegex.MatchString(mechanism):
		slog.Debug("Adding IP mechanism", "mechanism", mechanism)
		r.MapIPs[mechanism] = true
	// Convert A/AAAA and MX records, then add to r.MapIPs
	case mechanism == "a": // a
		return r.ConvertDomainToIP(domain, "", childNode)
	case aPrefixRegex.MatchString(mechanism): // a/<prefix-length>
		return r.ConvertDomainToIP(domain, mechanism[1:], childNode)
	case aDomainPrefixRegex.MatchString(mechanism): // a:<domain>/<prefix-length>
		return r.ConvertDomainToIP(mechanism[2:lastSlashIndex], mechanism[lastSlashIndex:], childNode)
	case aDomainRegex.MatchString(mechanism): // a:<domain>
		return r.ConvertDomainToIP(mechanism[2:], "", childNode)
	case mechanism == "mx": // mx
		return r.ConvertMxToIP(domain, "", childNode)
	case mxPrefixRegex.MatchString(mechanism): // mx/<prefix-length>
		return r.ConvertMxToIP(domain, mechanism[2:], childNode)
	case mxDomainPrefixRegex.MatchString(mechanism): // mx:<domain>/<prefix-length>
		return r.ConvertMxToIP(mechanism[3:lastSlashIndex], mechanism[lastSlashIndex:], childNode)
	case mxDomainRegex.MatchString(mechanism): // mx:<domain>
		return r.ConvertMxToIP(mechanism[3:], "", childNode)
	// Add ptr, exists, and exp mechanisms to r.MapNonflat
	case mechanism == "ptr":
		slog.Debug("Adding nonflat mechanism", "mechanism", mechanism+":"+domain)
		r.MapNonflat[mechanism+":"+domain] = true
	case nonflatRegex.MatchString(mechanism):
		slog.Debug("Adding nonflat mechanism", "mechanism", mechanism)
		r.MapNonflat[mechanism] = true
	// Recursive call to FlattenSPF on `include` and `redirect` mechanism
	case includeOrRedirectRegex.MatchString(mechanism):
		return r.FlattenSPF(mechanism[strings.IndexAny(mechanism, ":=")+1:], "", childNode)
	// Return error if no match
	default:
		return fmt.Errorf("received unexpected SPF mechanism or syntax: '%s'", mechanism)
	}
	return nil
}

// Convert A/AAAA records to IPs and add them to r.MapIPs
func (r *RootSPF) ConvertDomainToIP(domain, prefixLength string, parent Node) error {
	slog.Debug("Looking up IP records for domain", "domain", domain)
	ips, err := r.LookupIF.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("could not lookup IPs for %s: %s\n", domain, err)
	}
	for _, ip := range ips {
		childNode := &node{name: writeIPMech(ip, prefixLength), parent: parent}
		parent.AddChild(childNode)
		slog.Debug("Adding IP mechanism", "mechanism", writeIPMech(ip, prefixLength))
		r.MapIPs[writeIPMech(ip, prefixLength)] = true
	}
	return nil
}

// Convert MX records to domains then to IPs and add them to r.MapIPs
func (r *RootSPF) ConvertMxToIP(domain, prefixLength string, parent Node) error {
	slog.Debug("Looking up MX records for domain", "domain", domain)
	mxs, err := r.LookupIF.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("could not lookup MX records for %s: %s\n", domain, err)
	}
	for _, mx := range mxs {
		childNode := &node{name: mx.Host, parent: parent}
		parent.AddChild(childNode)
		slog.Debug("Found MX record for domain", "mx_record", mx.Host)
		if err := r.ConvertDomainToIP(mx.Host, prefixLength, childNode); err != nil {
			return fmt.Errorf("could not lookup IPs for MX record `%s`: %s\n", mx.Host, err)
		}
	}
	return nil
}

// Remove all mechanisms flattened by "keeps", add "keeps" to r.MapNonflat
// and count DNS lookups required by final SPF record
func (r *RootSPF) UnflattenKeeps() {
	r.LookupCount += len(r.MapNonflat)
	for _, keep := range strings.Fields(r.Keeps) {
		if keepNode := r.TraceTree.FindNode(keep); keepNode != nil {
			keepSubtree := r.TraceTree.GetSubtree(keepNode, []string{})
			for _, node := range keepSubtree {
				if !strings.HasPrefix(node, "ip") && !strings.HasSuffix(node, "all") {
					r.LookupCount += 1
				}
				delete(r.MapIPs, node)
				delete(r.MapNonflat, node)
			}
			r.MapNonflat[keep] = true
		}
	}
}

// Flatten and write new SPF record for root domain by compiling r.AllMechanism, r.MapIPs, and r.MapNonflat
func (r *RootSPF) WriteFlatSPF() string {
	r.UnflattenKeeps()
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
