package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/letsencrypt/spf-flattener/internal/spf"
)

type flags struct {
	rootDomain string
	initialSPF string
	logLevel   slog.Level
	dryrun     bool
	warn       bool
	url        string
	authEmail  string
	authKey    string
}

var levelInfoRegex = regexp.MustCompile(`^((L|l)evel)?((I|i)nfo)$`)
var levelWarnRegex = regexp.MustCompile(`^((L|l)evel)?((W|w)arn)$`)
var levelErrorRegex = regexp.MustCompile(`^((L|l)evel)?((E|e)rror)$`)
var levelDebugRegex = regexp.MustCompile(`^((L|l)evel)?((D|d)ebug)$`)

// Parse, check, and return flag inputs
func parseFlags() (flags, error) {
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
	f := flags{rootDomain: *rootDomainF, initialSPF: *ogRecordF, dryrun: *dryrunF, warn: *warnF,
		url: *urlF, authEmail: *authEmailF, authKey: *authKeyF}

	// Require domain to be nonempty
	if f.rootDomain == "" {
		return flags{}, fmt.Errorf("must provide a domain to flatten SPF record for. Use '-domain <yourdomain>'")
	}
	if strings.Contains(f.rootDomain, " ") || strings.Contains(f.rootDomain, ",") {
		return flags{}, fmt.Errorf("must provide only one domain for flattening")
	}

	// Set logLevel
	switch {
	case levelInfoRegex.MatchString(*logLevelF):
		f.logLevel = slog.LevelInfo
	case levelWarnRegex.MatchString(*logLevelF):
		f.logLevel = slog.LevelWarn
	case levelErrorRegex.MatchString(*logLevelF):
		f.logLevel = slog.LevelError
	case levelDebugRegex.MatchString(*logLevelF):
		f.logLevel = slog.LevelDebug
	default:
		return flags{}, fmt.Errorf("Unexpected logLevel; must be one of `debug`, `info`, `warn` or `error`")
	}

	// Require url, authEmail, and authKey to be nonempty if dryrun is false
	if !f.dryrun && (f.url == "" || f.authEmail == "" || f.authKey == "") {
		return flags{}, fmt.Errorf("'url', 'authEmail', and 'authKey' flags cannot be blank if 'dryrun' set to false")
	}

	return f, nil
}

func main() {
	// Parse input
	inputs, err := parseFlags()
	if err != nil {
		slog.Error("Could not parse flags", "error", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: inputs.logLevel}))
	slog.SetDefault(logger)

	/// Flatten SPF record for input domain
	r := spf.NewRootSPF(inputs.rootDomain, spf.NetLookup{})
	if err = r.FlattenSPF(r.RootDomain, inputs.initialSPF); err != nil {
		slog.Error("Could not flatten SPF record for initial domain", "error", err)
		os.Exit(1)
	}
	flatSPF := r.WriteFlatSPF()

	// Output flattened SPF record
	slog.Info("Successfully flattened SPF record for initial domain", "flattened_record", flatSPF)

	if inputs.warn {
		// Compare flattened SPF to SPF record currently set for r.RootDomain
		currentSPF, err := spf.GetDomainSPFRecord(r.RootDomain, r.LookupIF)
		if err != nil {
			slog.Error("Could not get current SPF record for initial domain", "error", err)
			os.Exit(1)
		}
		same, inCurrent, inFlat := spf.CompareRecords(currentSPF, flatSPF)
		if same {
			slog.Info("SPF record is unchanged")
			return
		}
		slog.Warn("Flattened SPF record differs from intiail SPF record", "removed_from_initial", inCurrent, "added_in_flattened", inFlat)
	}
	if inputs.dryrun {
		slog.Info("Dryrun complete")
		return
	}

	// Export flattened SPF record
	if err = spf.UpdateSPFRecord(r.RootDomain, flatSPF, inputs.url, inputs.authEmail, inputs.authKey); err != nil {
		slog.Error("Could not export flattened SPF record", "error", err)
		os.Exit(1)
	}
	slog.Info("Sucessfully updated SPF record")
}
