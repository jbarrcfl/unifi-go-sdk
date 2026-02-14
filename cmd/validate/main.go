package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/jbarrcfl/unifi-go-sdk/pkg/unifi"
)

type ValidationResult struct {
	Endpoint      string   `json:"endpoint"`
	MissingFields []string `json:"missingFields,omitempty"`
	Status        string   `json:"status"`
}

type Report struct {
	API      string             `json:"api"`
	Results  []ValidationResult `json:"results"`
	HasDrift bool               `json:"hasDrift"`
}

func main() {
	loadEnv(".env")

	apiKey := os.Getenv("UNIFI_API_KEY")
	networkURL := os.Getenv("UNIFI_NETWORK_URL")
	networkUser := os.Getenv("UNIFI_NETWORK_USER")
	networkPass := os.Getenv("UNIFI_NETWORK_PASS")

	var reports []Report

	if apiKey != "" {
		report := validateSiteManagerAPI(apiKey)
		reports = append(reports, report)
	}

	if networkURL != "" && networkUser != "" && networkPass != "" {
		report := validateNetworkAPI(networkURL, networkUser, networkPass)
		reports = append(reports, report)
	}

	if len(reports) == 0 {
		log.Fatal("No API credentials provided. Set UNIFI_API_KEY for Site Manager API or UNIFI_NETWORK_URL/USER/PASS for Network API")
	}

	output, _ := json.MarshalIndent(reports, "", "  ")
	fmt.Println(string(output))

	for _, r := range reports {
		if r.HasDrift {
			os.Exit(1)
		}
	}
}

func validateSiteManagerAPI(apiKey string) Report {
	report := Report{API: "site-manager"}

	client, err := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
		APIKey: apiKey,
	})
	if err != nil {
		report.Results = append(report.Results, ValidationResult{
			Endpoint: "client",
			Status:   fmt.Sprintf("client error: %v", err),
		})
		return report
	}
	report.Results = append(report.Results, validateHosts(client))
	report.Results = append(report.Results, validateSites(client))
	report.Results = append(report.Results, validateDevices(client))

	for _, r := range report.Results {
		if len(r.MissingFields) > 0 {
			report.HasDrift = true
			break
		}
	}

	return report
}

func validateNetworkAPI(url, user, pass string) Report {
	report := Report{API: "network"}

	client, err := unifi.NewNetworkClient(unifi.NetworkClientConfig{
		BaseURL:            url,
		Username:           user,
		Password:           pass,
		InsecureSkipVerify: true,
	})
	if err != nil {
		report.Results = append(report.Results, ValidationResult{
			Endpoint: "login",
			Status:   fmt.Sprintf("client error: %v", err),
		})
		return report
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	if err := client.Login(ctx); err != nil {
		report.Results = append(report.Results, ValidationResult{
			Endpoint: "login",
			Status:   fmt.Sprintf("login error: %v", err),
		})
		return report
	}
	defer client.Logout(context.Background())

	report.Results = append(report.Results, validateNetworkConf(client))
	report.Results = append(report.Results, validateFirewallRules(client))
	report.Results = append(report.Results, validateFirewallGroups(client))
	report.Results = append(report.Results, validatePortForwards(client))
	report.Results = append(report.Results, validateWLANConf(client))
	report.Results = append(report.Results, validatePortConf(client))
	report.Results = append(report.Results, validateRouting(client))
	report.Results = append(report.Results, validateUserGroups(client))
	report.Results = append(report.Results, validateRADIUSProfiles(client))
	report.Results = append(report.Results, validateDynamicDNS(client))

	for _, r := range report.Results {
		if len(r.MissingFields) > 0 {
			report.HasDrift = true
			break
		}
	}

	return report
}

func validateHosts(client *unifi.SiteManagerClient) ValidationResult {
	result := ValidationResult{Endpoint: "/v1/hosts", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := newAPIRequest(ctx, client, "/v1/hosts?pageSize=1")
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}
	defer resp.Body.Close()

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		result.Status = fmt.Sprintf("decode error: %v", err)
		return result
	}

	data, ok := raw["data"].([]interface{})
	if !ok || len(data) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	hostMap, ok := data[0].(map[string]interface{})
	if !ok {
		result.Status = "invalid host data"
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.Host{}))
	result.MissingFields = findMissingFields(hostMap, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateSites(client *unifi.SiteManagerClient) ValidationResult {
	result := ValidationResult{Endpoint: "/v1/sites", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := newAPIRequest(ctx, client, "/v1/sites?pageSize=1")
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}
	defer resp.Body.Close()

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		result.Status = fmt.Sprintf("decode error: %v", err)
		return result
	}

	data, ok := raw["data"].([]interface{})
	if !ok || len(data) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	siteMap, ok := data[0].(map[string]interface{})
	if !ok {
		result.Status = "invalid site data"
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.Site{}))
	result.MissingFields = findMissingFields(siteMap, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateDevices(client *unifi.SiteManagerClient) ValidationResult {
	result := ValidationResult{Endpoint: "/v1/devices", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := newAPIRequest(ctx, client, "/v1/devices?pageSize=1")
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}
	defer resp.Body.Close()

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		result.Status = fmt.Sprintf("decode error: %v", err)
		return result
	}

	data, ok := raw["data"].([]interface{})
	if !ok || len(data) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	hostDevicesMap, ok := data[0].(map[string]interface{})
	if !ok {
		result.Status = "invalid host devices data"
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.HostDevices{}))
	missing := findMissingFields(hostDevicesMap, structFields, "")

	devices, ok := hostDevicesMap["devices"].([]interface{})
	if ok && len(devices) > 0 {
		deviceMap, ok := devices[0].(map[string]interface{})
		if ok {
			deviceFields := getJSONFields(reflect.TypeOf(unifi.Device{}))
			deviceMissing := findMissingFields(deviceMap, deviceFields, "devices[].")
			missing = append(missing, deviceMissing...)
		}
	}

	result.MissingFields = missing
	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

const requestTimeout = 30 * time.Second

func newAPIRequest(ctx context.Context, client *unifi.SiteManagerClient, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", client.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", client.APIKey)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func getJSONFields(t reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		jsonName := strings.Split(tag, ",")[0]
		fields[jsonName] = field.Type
	}

	return fields
}

func findMissingFields(data map[string]interface{}, structFields map[string]reflect.Type, prefix string) []string {
	var missing []string

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if _, exists := structFields[key]; !exists {
			missing = append(missing, prefix+key)
		}
	}

	return missing
}

func validateNetworkConf(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "networkconf", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	networks, err := client.ListNetworks(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(networks) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "networkconf")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.Network{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateFirewallRules(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "firewallrule", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	rules, err := client.ListFirewallRules(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(rules) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "firewallrule")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.FirewallRule{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateFirewallGroups(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "firewallgroup", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	groups, err := client.ListFirewallGroups(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(groups) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "firewallgroup")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.FirewallGroup{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validatePortForwards(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "portforward", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	forwards, err := client.ListPortForwards(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(forwards) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "portforward")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.PortForward{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateWLANConf(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "wlanconf", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	wlans, err := client.ListWLANs(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(wlans) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "wlanconf")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.WLANConf{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validatePortConf(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "portconf", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	confs, err := client.ListPortConfs(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(confs) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "portconf")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.PortConf{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateRouting(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "routing", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	routes, err := client.ListRoutes(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(routes) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "routing")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.Routing{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateUserGroups(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "usergroup", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	groups, err := client.ListUserGroups(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(groups) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "usergroup")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.UserGroup{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateRADIUSProfiles(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "radiusprofile", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	profiles, err := client.ListRADIUSProfiles(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(profiles) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "radiusprofile")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.RADIUSProfile{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func validateDynamicDNS(client *unifi.NetworkClient) ValidationResult {
	result := ValidationResult{Endpoint: "dynamicdns", Status: "ok"}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	configs, err := client.ListDynamicDNS(ctx)
	if err != nil {
		result.Status = fmt.Sprintf("error: %v", err)
		return result
	}

	if len(configs) == 0 {
		result.Status = "skipped (no data)"
		return result
	}

	raw, err := fetchNetworkRaw(client, "dynamicdns")
	if err != nil {
		result.Status = fmt.Sprintf("raw fetch error: %v", err)
		return result
	}

	structFields := getJSONFields(reflect.TypeOf(unifi.DynamicDNS{}))
	result.MissingFields = findMissingFields(raw, structFields, "")

	if len(result.MissingFields) > 0 {
		result.Status = "drift detected"
	}

	return result
}

func fetchNetworkRaw(client *unifi.NetworkClient, endpoint string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	url := client.BaseURL + "/proxy/network/api/s/" + client.Site + "/rest/" + endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var raw struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	if len(raw.Data) == 0 {
		return nil, fmt.Errorf("no data returned")
	}

	return raw.Data[0], nil
}

func loadEnv(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}
}
