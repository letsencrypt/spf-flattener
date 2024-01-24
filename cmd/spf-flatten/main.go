package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"

	"github.com/letsencrypt/spf-flattener/internal/spf"
)

type netLookup struct{}

func (n netLookup) LookupTXT(s string) ([]string, error) {
	return net.LookupTXT(s)
}
func (n netLookup) LookupIP(s string) ([]net.IP, error) {
	return net.LookupIP(s)
}
func (n netLookup) LookupMX(s string) ([]*net.MX, error) {
	return net.LookupMX(s)
}

// INPUT/OUTPUT PROCESSING ====================================================================

// Parse, check, and return flag inputs
func parseFlags() (rootDomain, initialSPF string, logLevel slog.Level, dryrun bool, warn bool, url string, authEmail string, authKey string, err error) {
	rootDomainF := flag.String("domain", "", "Initial domain to set SPF record for") // required
	ogRecordF := flag.String("initialSPF", "", "Initial SPF record to flatten")      // optional
	logLevelF := flag.String("logLevel", "LevelInfo", "")                            // optional
	dryrunF := flag.Bool("dryrun", true, "")                                         // optional
	warnF := flag.Bool("warn", true, "")                                             // optional TODO: come up with better name
	urlF := flag.String("url", "", "API URL for SPF record")                         // optional unless dryrun is false
	authEmailF := flag.String("authEmail", "", "API key for X-Auth-Email header")    // optional unless dryrun is false
	authKeyF := flag.String("authKey", "", "API key for X-Auth-Key header")          // optional unless dryrun is false
	// TBD: should url, authEmail, and authKey be retrieved from os.Getenv instead of passed as flags?
	// TBD: possible flags to add in the future: list of mechanisms to ignore or fail on, timeout/max recursions
	flag.Parse()

	// Require domain to be nonempty
	if *rootDomainF == "" {
		err = fmt.Errorf("must provide a domain to flatten SPF record for. Use '-domain <yourdomain>'")
		return
	}

	// Set logLevel
	switch {
	case regexp.MustCompile(`^((L|l)evel)?((I|i)nfo)$`).MatchString(*logLevelF):
		logLevel = slog.LevelInfo
	case regexp.MustCompile(`^((L|l)evel)?((W|w)arn)$`).MatchString(*logLevelF):
		logLevel = slog.LevelWarn
	case regexp.MustCompile(`^((L|l)evel)?((E|e)rror)$`).MatchString(*logLevelF):
		logLevel = slog.LevelError
	case regexp.MustCompile(`^((L|l)evel)?((D|d)ebug)$`).MatchString(*logLevelF):
		logLevel = slog.LevelDebug
	default:
		err = fmt.Errorf("Unexpected logLevel; must be one of `debug`, `info`, `warn` or `error`")
		return
	}

	// Require url, authEmail, and authKey to be nonempty if dryrun is false
	if !*dryrunF && (*urlF == "" || *authEmailF == "" || *authKeyF == "") {
		err = fmt.Errorf("'url', 'authEmail', and 'authKey' flags cannot be blank if 'dryrun' set to false")
		return
	}

	return *rootDomainF, *ogRecordF, logLevel, *dryrunF, *warnF, *urlF, *authEmailF, *authKeyF, nil
}

// MAIN =======================================================================================

func main() {
	// Parse input
	rootDomain, initialSPF, logLevel, dryrun, warn, url, authEmail, authKey, err := parseFlags()
	if err != nil {
		slog.Error("Could not parse flags", "error", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	/// Do the stuff
	r := spf.RootSPF{RootDomain: rootDomain, MapIPs: map[string]bool{}, MapNonflat: map[string]bool{}, LookupIF: netLookup{}}
	initialSPF, err = r.CheckSPFRecord(r.RootDomain, initialSPF)
	if err != nil {
		slog.Error("Could not lookup SPF record for initial domain", "error", err)
	}

	if err = r.FlattenSPF(r.RootDomain, initialSPF); err != nil {
		slog.Error("Could not flatten SPF record for initial domain", "error", err)
		return
	}
	flatSPF := r.WriteFlatSPF()

	// Output flattened SPF record
	slog.Info("Successfully flattened SPF record for initial domain", "flattened_record", flatSPF)

	if warn {
		same, inInitial, inFlat := spf.CompareRecords(initialSPF, flatSPF)
		if same {
			slog.Info("SPF record is unchanged")
			return
		}
		slog.Warn("Flattened SPF record differs from intiail SPF record", "removed_from_initial", inInitial, "added_in_flattened", inFlat)
	}
	if dryrun {
		return
	}

	// Export flattened SPF record
	if err = spf.UpdateSPFRecord(r.RootDomain, flatSPF, url, authEmail, authKey); err != nil {
		slog.Error("Could not export flattened SPF record", "error", err)
	}
	slog.Info("Sucessfully updated SPF record")
}
