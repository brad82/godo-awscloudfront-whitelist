package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/digitalocean/godo"
)

const AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

type AwsNetworkInfoResponse struct {
	SyncToken string                 `json:"syncToken"`
	Prefixes  []AwsNetworkAssignment `json:"prefixes"`
}

type AwsNetworkAssignment struct {
	Address            string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

func fetchRanges(service string) ([]string, error) {
	res, err := http.Get(AWS_RANGES_URL)

	if err != nil {
		return nil, err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	networkMapResponse := AwsNetworkInfoResponse{}
	jsonErr := json.Unmarshal(body, &networkMapResponse)
	if jsonErr != nil {
		return nil, err
	}

	addresses := []string{}
	for i := 0; i < len(networkMapResponse.Prefixes); i++ {
		if networkMapResponse.Prefixes[i].Service == service {
			addresses = append(addresses, networkMapResponse.Prefixes[i].Address)
		}
	}

	return addresses, nil
}

func main() {
	DO_API_TOKEN := os.Getenv("DO_API_TOKEN")

	if len(os.Args) != 2 {
		fmt.Println("Usage:", os.Args[0], "FIREWALL_GUID")
		return
	}

	firewallGuid := os.Args[1]

	addresses, requestErr := fetchRanges("CLOUDFRONT")
	if requestErr != nil {
		log.Fatal(requestErr)
		return
	}

	godoClient := godo.NewFromToken(DO_API_TOKEN)
	ctx := context.TODO()

	ports := []string{"443", "80"}
	for _, port := range ports {
		ruleRequest := &godo.FirewallRulesRequest{
			InboundRules: []godo.InboundRule{
				{
					Protocol:  "tcp",
					PortRange: port,
					Sources: &godo.Sources{
						Addresses: addresses,
					},
				},
			},
		}

		_, err := godoClient.Firewalls.AddRules(ctx, firewallGuid, ruleRequest)
		if err != nil {
			log.Fatal(err)
		}
	}
}
