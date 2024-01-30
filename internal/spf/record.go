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

// Return the SPF record for the given domain
func GetDomainSPFRecord(domain string, lookupIF Lookup) (string, error) {
	txtRecords, err := lookupIF.LookupTXT(domain)
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
func CheckSPFRecord(domain, spfRecord string, lookupIF Lookup) (string, error) {
	if spfRecord == "" {
		record, err := GetDomainSPFRecord(domain, lookupIF)
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
