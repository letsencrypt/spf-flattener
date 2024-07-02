// GET, CHECK, COMPARE, and OUPUT SPF RECORDS =================================================
package spf

import (
	"encoding/json"
	"fmt"
	"io"
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

// Make HTTP request of type kind to url with body and
// authEmail and authKey authorization headers. If target not nil,
// then json decode response body and store in target. Return error
func MakeHTTPRequest(url, kind, authEmail, authKey string, body io.Reader, target interface{}) error {
	req, _ := http.NewRequest(kind, url, body)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Auth-Email", authEmail)
	req.Header.Add("Authorization", "Bearer "+authKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("could not make HTTP request: %s", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("HTTP request unsuccessful: got status code %d", res.StatusCode)
	}
	if target != nil {
		if err := json.NewDecoder(res.Body).Decode(target); err != nil {
			return fmt.Errorf("could not json decode response body: %s", err)
		}
	}
	return nil
}

type ZonesResponse struct {
	Result []struct {
		Id string `json:"id"`
	}
}

// Get the zone ID of rootDomain's zone
func GetZoneID(rootDomain, authEmail, authKey string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", rootDomain)
	results := new(ZonesResponse)
	err := MakeHTTPRequest(url, "GET", authEmail, authKey, nil, results)
	if err != nil {
		return "", fmt.Errorf("error looking up DNS zone for %s: %s", rootDomain, err)
	}
	if len(results.Result) > 1 {
		return "", fmt.Errorf("found more than one DNS zone for %s", rootDomain)
	}
	return results.Result[0].Id, nil
}

type RecordsResponse struct {
	Result []struct {
		Id      string `json:"id"`
		Content string `json:"content"`
	}
}

// Get the record ID of rootDomain's SPF record
func GetRecordID(rootDomain, authEmail, authKey, zone_id string) (string, error) {
	// Get all TXT records in rootDomain's zone with the rootDomain as the name
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=TXT&name=%s", zone_id, rootDomain)
	results := new(RecordsResponse)

	err := MakeHTTPRequest(url, "GET", authEmail, authKey, nil, results)
	if err != nil {
		return "", fmt.Errorf("error looking up TXT records for %s: %s", rootDomain, err)
	}

	// Filter for SPF record and record it's record_id
	record_id := ""
	for _, record := range results.Result {
		if strings.HasPrefix(record.Content, "v=spf1") {
			if record_id != "" {
				return "", fmt.Errorf("found more than one SPF record for %s", rootDomain)
			}
			record_id = record.Id
		}
	}
	return record_id, nil
}

// Lookup up the zone_id and record_id of rootDomain's SPF record and then
// write and return the url based on those values
func GetRecordURL(rootDomain, authEmail, authKey string) (string, error) {
	zone_id, err := GetZoneID(rootDomain, authEmail, authKey)
	if err != nil {
		return "", fmt.Errorf("could not get zone_id of %s: %s", rootDomain, err)
	}
	record_id, err := GetRecordID(rootDomain, authEmail, authKey, zone_id)
	if err != nil {
		return "", fmt.Errorf("could not get record_id of %s's SPF record: %s", rootDomain, err)
	}
	return fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zone_id, record_id), nil
}

type PatchRequest struct {
	Content string `json:"content"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
}

// PATCH the updated, flattened SPF record
func UpdateSPFRecord(rootDomain, flatSPF, url, authEmail, authKey string) error {
	if len(flatSPF) > 2048 {
		return fmt.Errorf("SPF record is too long (got %d > 2048 characters)", len(flatSPF))
	}
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

	// If url not provided, get API URL for rootDomain's SPF record
	if url == "" {
		record_url, err := GetRecordURL(rootDomain, authEmail, authKey)
		if err != nil {
			return err
		}
		url += record_url
	}

	err = MakeHTTPRequest(url, "PATCH", authEmail, authKey, strings.NewReader(string(payload)), nil)
	if err != nil {
		return err
	}
	return nil
}
