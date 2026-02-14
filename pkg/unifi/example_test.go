package unifi_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/jbarrcfl/unifi-go-sdk/pkg/unifi"
)

func ExampleNewSiteManagerClient() {
	client, err := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
		APIKey: "your-api-key",
	})
	if err != nil {
		log.Fatal(err)
	}

	hosts, err := client.ListAllHosts(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	for _, host := range hosts {
		fmt.Printf("Host: %s (%s)\n", host.ID, host.Type)
	}
}

func ExampleNewNetworkClient() {
	client, err := unifi.NewNetworkClient(unifi.NetworkClientConfig{
		BaseURL:            "https://192.168.1.1",
		Username:           "admin",
		Password:           "password",
		Site:               "default",
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	if err := client.Login(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Logout(ctx)

	networks, err := client.ListNetworks(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d networks\n", len(networks))
}

func ExampleNetworkClient_CreateNetwork() {
	client, err := unifi.NewNetworkClient(unifi.NetworkClientConfig{
		BaseURL:  "https://192.168.1.1",
		Username: "admin",
		Password: "password",
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	if err := client.Login(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Logout(ctx)

	network, err := client.CreateNetwork(ctx, &unifi.Network{
		Name:    "IoT Network",
		Purpose: "corporate",
		Enabled: unifi.BoolPtr(true),
		NetworkVLAN: unifi.NetworkVLAN{
			VLAN:        unifi.IntPtr(100),
			VLANEnabled: unifi.BoolPtr(true),
			IPSubnet:    "10.0.100.1/24",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created network: %s\n", network.ID)
}

func Example_errorHandling() {
	client, _ := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
		APIKey: "your-api-key",
	})

	_, err := client.GetHost(context.Background(), "invalid-id")

	// Check for specific error types
	if errors.Is(err, unifi.ErrNotFound) {
		fmt.Println("Host not found")
	}
	if errors.Is(err, unifi.ErrUnauthorized) {
		fmt.Println("Invalid API key")
	}

	// Get detailed error information
	var apiErr *unifi.APIError
	if errors.As(err, &apiErr) {
		fmt.Printf("Status: %d, Message: %s\n", apiErr.StatusCode, apiErr.Message)
	}
}

func Example_pointerHelpers() {
	// Use pointer helpers for optional fields
	rule := &unifi.FirewallRule{
		Name:      "Block IOT to LAN",
		Enabled:   unifi.BoolPtr(true),
		Action:    "drop",
		RuleIndex: unifi.IntPtr(2000),
		Protocol:  "all",
	}

	fmt.Printf("Rule: %s, Enabled: %v\n", rule.Name, *rule.Enabled)
	// Output: Rule: Block IOT to LAN, Enabled: true
}

func Example_firewallPolicyBuilder() {
	// Use builders for complex structs like FirewallPolicy
	policy := unifi.NewFirewallPolicyBuilder().
		Name("Block IoT to LAN").
		Action("DROP").
		Protocol("all").
		Logging(true).
		SourceFrom(
			unifi.NewPolicyEndpointBuilder().
				ZoneID("iot-zone-id").
				MatchingTarget("ANY"),
		).
		DestinationFrom(
			unifi.NewPolicyEndpointBuilder().
				ZoneID("lan-zone-id").
				Port("22").
				PortMatchingType("SPECIFIC"),
		).
		ScheduleFrom(
			unifi.NewPolicyScheduleBuilder().
				Custom("09:00", "17:00", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"),
		).
		Build()

	fmt.Printf("Policy: %s, Action: %s, Enabled: %v\n", policy.Name, policy.Action, *policy.Enabled)
	// Output: Policy: Block IoT to LAN, Action: DROP, Enabled: true
}
