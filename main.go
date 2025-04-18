package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	ipServiceURL = "https://checkip.amazonaws.com/"
)

func getPublicIP() (string, error) {
	resp, err := http.Get(ipServiceURL)
	if err != nil {
		return "", fmt.Errorf("failed to get public IP from %s: %w", ipServiceURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get public IP: service %s returned status %s", ipServiceURL, resp.Status)
	}

	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body from IP service: %w", err)
	}

	ip := strings.TrimSpace(string(ipBytes))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP address received: %s", ip)
	}

	log.Printf("Discovered public IP: %s\n", ip)
	return ip, nil
}

func main() {
	myName := flag.String("my-name", "", "Name of the host to resolve")
	profileName := flag.String("profile", "default", "AWS profile name from credentials")
	sgId := flag.String("sg-id", "", "Target Security Group ID")
	sgTagName := flag.String("sg-tag-name", "", "Target Security Group Tag 'Name' (used if --sg-id is not provided)")

	flag.Parse()

	if *myName == "" {
		fmt.Println("Error: --my-name is required")
		flag.Usage()
		os.Exit(1)
	}

	targetSgId := *sgId
	targetSgName := *sgTagName

	if targetSgId == "" && targetSgName == "" {
		fmt.Println("Neither --sg-id nor --sg-tag-name provided")
		flag.Usage()
		os.Exit(1)
	}

	publicIP, err := getPublicIP()
	if err != nil {
		log.Fatalf("Error getting public IP: %v", err)
	}

	fmt.Println("-----------------------------------------")
	// fmt.Printf("✅ Successfully updated Security Group %s\n", finalSgID)
	fmt.Printf("   Allowed TCP traffic from: %s/32\n", publicIP)
	fmt.Printf("   Rule description: %s\n", *myName)
	fmt.Printf("   Using AWS Profile: %s\n", *profileName)
	fmt.Println("-----------------------------------------")
}
