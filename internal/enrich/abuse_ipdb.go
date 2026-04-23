package enrich

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/viper"
)

const (
	abuseipdb_root = "https://api.abuseipdb.com/api/v2/"
	abuseipdb      = "abuseipdb_api_key"
)

type Reports struct {
	ReportedAt          time.Time `json:"reportedAt"`
	Comment             string    `json:"comment"`
	Categories          []int     `json:"categories"`
	ReporterId          int       `json:"reporterId"`
	ReporterCountryCode string    `json:"reporterCountryCode"`
	ReporterCountryName string    `json:"reporterCountryName"`
}

type RootData struct {
	IpAddress            string        `json:"ipAddress"`
	IsPublic             bool          `json:"isPublic"`
	IpVersion            int           `json:"ipVersion"`
	IsWhitelisted        bool          `json:"isWhitelisted"`
	AbuseConfidenceScore int           `json:"abuseConfidenceScore"`
	CountryCode          string        `json:"countryCode"`
	CountryName          string        `json:"countryName"`
	UsageType            string        `json:"usageType"`
	Isp                  string        `json:"isp"`
	Domain               string        `json:"domain"`
	Hostnames            []interface{} `json:"hostnames"`
	IsTor                bool          `json:"isTor"`
	TotalReports         int           `json:"totalReports"`
	NumDistinctUsers     int           `json:"numDistinctUsers"`
	LastReportedAt       time.Time     `json:"lastReportedAt"`
	Reports              []Reports     `json:"reports"`
}

type AbuseIpDbResponse struct {
	Data RootData `json:"data"`
}

type AbuseIPClient struct {
	// probably some channel to not be gated by HTTP lag
}

func NewAbuseIPClient() *AbuseIPClient {
	return &AbuseIPClient{}
}

func (c *AbuseIPClient) Lookup(ip string) {
	checkUrl := fmt.Sprintf("%s%s", abuseipdb_root, "check")
	rawUrl, err := url.Parse(checkUrl)
	if err != nil {
		return
	}

	values := url.Values{}
	values.Set("ipAddress", ip)

	rawUrl.RawQuery = values.Encode()

	checkUrl = rawUrl.String()
	fmt.Println("checkUrl:", checkUrl)

	req, err := http.NewRequest(http.MethodGet, checkUrl, nil)
	if err != nil {
		return
	}

	req.Header.Add("Key", getApiKey())
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var abuseIpDbResponse *AbuseIpDbResponse
	if err := json.Unmarshal(bodyBytes, abuseIpDbResponse); err != nil {
		return
	}

	fmt.Printf("%+v\n", abuseIpDbResponse)
}

// getApiKey gets the API key from the viper config
func getApiKey() string {
	return viper.GetString(abuseipdb)
}
