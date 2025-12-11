package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/resnickio/unifi-go-sdk/pkg/unifi"
)

type ValidationResult struct {
	Endpoint      string   `json:"endpoint"`
	MissingFields []string `json:"missingFields,omitempty"`
	Status        string   `json:"status"`
}

type Report struct {
	Results []ValidationResult `json:"results"`
	HasDrift bool              `json:"hasDrift"`
}

func main() {
	apiKey := os.Getenv("UNIFI_API_KEY")
	if apiKey == "" {
		log.Fatal("UNIFI_API_KEY environment variable is required")
	}

	client := unifi.NewSiteManagerClient(apiKey)

	var report Report

	report.Results = append(report.Results, validateHosts(client))
	report.Results = append(report.Results, validateSites(client))
	report.Results = append(report.Results, validateDevices(client))

	for _, r := range report.Results {
		if len(r.MissingFields) > 0 {
			report.HasDrift = true
			break
		}
	}

	output, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(output))

	if report.HasDrift {
		os.Exit(1)
	}
}

func validateHosts(client *unifi.SiteManagerClient) ValidationResult {
	result := ValidationResult{Endpoint: "/v1/hosts", Status: "ok"}

	req, err := newAPIRequest(client, "/v1/hosts?pageSize=1")
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

	req, _ := newAPIRequest(client, "/v1/sites?pageSize=1")
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

	req, _ := newAPIRequest(client, "/v1/devices?pageSize=1")
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

func newAPIRequest(client *unifi.SiteManagerClient, path string) (*http.Request, error) {
	req, err := http.NewRequest("GET", client.BaseURL+path, nil)
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
