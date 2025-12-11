package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/resnickio/unifi-go-sdk/pkg/unifi"
)

func main() {
	apiKey := os.Getenv("UNIFI_API_KEY")
	if apiKey == "" {
		log.Fatal("UNIFI_API_KEY is required")
	}

	client := unifi.NewSiteManagerClient(apiKey)

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
		fmt.Printf("Got host: %s (%s)\n", host.Host.ReportedState.Name, host.Host.ID)
	}
}
