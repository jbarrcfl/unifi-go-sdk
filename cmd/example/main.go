package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jbarrcfl/unifi-go-sdk/pkg/unifi"
)

func main() {
	apiKey := os.Getenv("UNIFI_API_KEY")
	if apiKey == "" {
		log.Fatal("UNIFI_API_KEY is required")
	}

	client, err := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
		APIKey: apiKey,
	})
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	hosts, err := client.ListAllHosts(context.Background())
	if err != nil {
		log.Fatalf("Error listing hosts: %v", err)
	}

	fmt.Printf("Found %d hosts\n", len(hosts))
	for _, host := range hosts {
		fmt.Printf("  Host: %s (%s)\n", host.ID, host.Type)
	}

	if len(hosts) > 0 {
		host, err := client.GetHost(context.Background(), hosts[0].ID)
		if err != nil {
			log.Fatalf("Error getting host: %v", err)
		}
		name := host.Host.ID
		if host.Host.ReportedState != nil {
			name = host.Host.ReportedState.Name
		}
		fmt.Printf("Got host: %s (%s)\n", name, host.Host.ID)
	}
}
