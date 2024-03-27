// GET, CHECK, COMPARE, and OUPUT SPF RECORDS =================================================
package spf

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

var levelInfoRegex = regexp.MustCompile(`^((L|l)evel)?((I|i)nfo)$`)
var levelWarnRegex = regexp.MustCompile(`^((L|l)evel)?((W|w)arn)$`)
var levelErrorRegex = regexp.MustCompile(`^((L|l)evel)?((E|e)rror)$`)
var levelDebugRegex = regexp.MustCompile(`^((L|l)evel)?((D|d)ebug)$`)

func GetLogLevel(inputLevel string) (slog.Level, error) {
	switch {
	case levelInfoRegex.MatchString(inputLevel):
		return slog.LevelInfo, nil
	case levelWarnRegex.MatchString(inputLevel):
		return slog.LevelWarn, nil
	case levelErrorRegex.MatchString(inputLevel):
		return slog.LevelError, nil
	case levelDebugRegex.MatchString(inputLevel):
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("unexpected log level; must be one of `debug`, `info`, `warn` or `error`")
	}
}

// Return the SPF record for the given domain
func GetDomainSPFRecord(domain string, lookupIF Lookup) (string, error) {
	txtRecords, err := lookupIF.LookupTXT(domain)
	if err != nil {
		return "", fmt.Errorf("could not look up SPF record for %s: %s\n", domain, err)
	}
	for _, record := range txtRecords {
		// TBD: check that only one SPF record lookupexists for domain and fail otherwise?
		if strings.HasPrefix(record, "v=spf1") {
			slog.Debug("Found SPF record", "domain", domain, "spf_record", record)
			return record, nil
		}
	}
	return "", fmt.Errorf("no SPF record found for %s", domain)
}

// Check that given record matches expected format and return error otherwise
func CheckSPFRecord(domain, spfRecord string, lookupIF Lookup) error {
	if strings.HasPrefix(spfRecord, "v=spf1") {
		return nil
	}
	return fmt.Errorf("SPF record for %s did not match expected format. Got '%s'", domain, spfRecord)
}

// Compare intial and flattened SPF records by checking that they both
// have the same entries regardless of order. Return any different entries.
func CompareRecords(startSPF, endSPF string) (bool, string, string) {
	startList, endList := strings.Split(startSPF, " "), strings.Split(endSPF, " ")
	sort.Strings(startList)
	sort.Strings(endList)

	var inStart strings.Builder
	var inEnd strings.Builder

	i, j := 0, 0
	for i < len(startList) || j < len(endList) {
		switch {
		case i < len(startList) && (j == len(endList) || startList[i] < endList[j]):
			inStart.WriteString(startList[i] + " ")
			i++
		case j < len(endList) && (i == len(startList) || startList[i] > endList[j]):
			inEnd.WriteString(endList[j] + " ")
			j++
		default:
			i++
			j++
		}
	}

	startDiff, endDiff := strings.TrimSpace(inStart.String()), strings.TrimSpace(inEnd.String())
	return (len(startDiff) == 0 && len(endDiff) == 0), startDiff, endDiff
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
	req.Header.Add("Authorization", "Bearer "+authKey)

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
