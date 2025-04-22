package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
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

func loadAWSConfig(ctx context.Context, profileName string) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profileName))
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS configuration for profile '%s': %w", profileName, err)
	}

	log.Printf("Loaded AWS configuration using profile: %s\n", profileName)

	if cfg.Region == "" {
		log.Println("Warning: AWS Region not specified in profile or environment variables. SDK might default to one (e.g., us-east-1) or fail if region is required.")
	} else {
		log.Printf("Using AWS Region: %s\n", cfg.Region)
	}

	return cfg, nil
}

func findSecurityGroupIDs(ctx context.Context, client *ec2.Client, sgIDs []string, sgTagNames []string) ([]string, error) {
	resolvedIDs := make(map[string]struct{})
	var errorList []string

	if len(sgIDs) > 0 {
		log.Printf("Attempting to verify %d provided Security Group ID(s)...\n", len(sgIDs))

		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, id := range sgIDs {
			if id == "" {
				continue
			}

			wg.Add(1)

			go func(sgID string) {
				defer wg.Done()

				input := &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{sgID},
				}

				_, err := client.DescribeSecurityGroups(ctx, input)

				mu.Lock()

				defer mu.Unlock()

				if err != nil {
					var apiErr *smithy.GenericAPIError
					if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidGroup.NotFound" {
						errorList = append(errorList, fmt.Sprintf("ID '%s' not found", sgID))
					} else {
						errorList = append(errorList, fmt.Sprintf("failed to verify ID '%s': %v", sgID, err))
					}
				} else {
					resolvedIDs[sgID] = struct{}{}
				}
			}(id)
		}

		wg.Wait()

		if len(errorList) > 0 {
			return nil, fmt.Errorf("encountered errors validating SG IDs: %s", strings.Join(errorList, "; "))
		}

		log.Printf("Successfully verified %d unique Security Group ID(s).\n", len(resolvedIDs))
	}

	if len(sgTagNames) > 0 {
		log.Printf("Searching for Security Groups with tag Name(s): %v\n", sgTagNames)

		input := &ec2.DescribeSecurityGroupsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("tag:Name"),
					Values: sgTagNames,
				},
			},
		}

		result, err := client.DescribeSecurityGroups(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe security groups with tags '%v': %w", sgTagNames, err)
		}

		if len(result.SecurityGroups) == 0 {
			log.Printf("Warning: No security groups found matching tag Name(s): %v\n", sgTagNames)
			return nil, nil
		} else {
			for _, sg := range result.SecurityGroups {
				resolvedIDs[*sg.GroupId] = struct{}{}
			}

			log.Printf("Found %d unique Security Group ID(s) matching tags.\n", len(resolvedIDs))
		}
	}

	finalIDs := make([]string, 0, len(resolvedIDs))

	for id := range resolvedIDs {
		finalIDs = append(finalIDs, id)
	}

	if len(finalIDs) == 0 && len(errorList) == 0 {
		log.Println("Warning: No valid or matching Security Group IDs were resolved.")
	}

	return finalIDs, nil
}

func syncSecurityGroupRule(ctx context.Context, client *ec2.Client, sgID, publicIP, description string) error {
	targetCidrIP := publicIP + "/32"
	ruleNeedsAdding := true
	var ruleToRevoke *types.IpPermission = nil

	log.Printf("[%s] Checking existing rules for description '%s'\n", sgID, description)

	descInput := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	}

	sgDesc, err := client.DescribeSecurityGroups(ctx, descInput)
	if err != nil {
		var apiErr *smithy.GenericAPIError

		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidGroup.NotFound" {
			return fmt.Errorf("[%s] Security group not found during rule sync", sgID)
		}

		return fmt.Errorf("[%s] Failed to describe security group: %w", sgID, err)
	}

	if len(sgDesc.SecurityGroups) == 0 {
		return fmt.Errorf("[%s] Security group description returned empty list", sgID)
	}

	theGroup := sgDesc.SecurityGroups[0]

	for _, ipPerm := range theGroup.IpPermissions {
		if aws.ToString(ipPerm.IpProtocol) == "tcp" && aws.ToInt32(ipPerm.FromPort) == 0 && aws.ToInt32(ipPerm.ToPort) == 65535 {
			var rangesToRevoke []types.IpRange

			for _, ipRange := range ipPerm.IpRanges {
				if aws.ToString(ipRange.Description) == description {
					if aws.ToString(ipRange.CidrIp) == targetCidrIP {
						log.Printf("[%s] Found existing rule for description '%s' with correct IP %s. No changes needed.\n", sgID, description, targetCidrIP)
						ruleNeedsAdding = false
						break
					} else {
						log.Printf("[%s] Found existing rule for description '%s' with outdated IP %s. Marking for removal.\n", sgID, description, aws.ToString(ipRange.CidrIp))
						rangesToRevoke = append(rangesToRevoke, ipRange)
					}
				}
			}

			if len(rangesToRevoke) > 0 {
				ruleToRevoke = &types.IpPermission{
					IpProtocol: ipPerm.IpProtocol,
					FromPort:   ipPerm.FromPort,
					ToPort:     ipPerm.ToPort,
					IpRanges:   rangesToRevoke,
				}

				break
			}

			if !ruleNeedsAdding {
				break
			}
		}
	}

	if ruleToRevoke != nil {
		log.Printf("[%s] Revoking outdated rule(s) for description '%s'...\n", sgID, description)

		revokeInput := &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: []types.IpPermission{*ruleToRevoke},
		}

		_, err := client.RevokeSecurityGroupIngress(ctx, revokeInput)
		if err != nil {
			var apiErr *smithy.GenericAPIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidPermission.NotFound" {
				log.Printf("[%s] Warning: Rule to revoke was not found (maybe already deleted): %v\n", sgID, err)
			} else {
				return fmt.Errorf("[%s] Failed to revoke old security group rule for '%s': %w", sgID, description, err)
			}
		} else {
			log.Printf("[%s] Successfully revoked outdated rule(s) for description '%s'.\n", sgID, description)
		}
	}

	if ruleNeedsAdding {
		log.Printf("[%s] Authorizing rule for description '%s' with IP %s...\n", sgID, description, targetCidrIP)

		authInput := &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId: aws.String(sgID),
			IpPermissions: []types.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int32(0),
					ToPort:     aws.Int32(65535),
					IpRanges: []types.IpRange{
						{
							CidrIp:      aws.String(targetCidrIP),
							Description: aws.String(description),
						},
					},
				},
			},
		}

		_, err := client.AuthorizeSecurityGroupIngress(ctx, authInput)
		if err != nil {
			var apiErr *smithy.GenericAPIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidPermission.Duplicate" {
				log.Printf("[%s] Rule for %s already exists (possibly added concurrently or revoke failed silently). No changes needed.\n", sgID, targetCidrIP)
			} else {
				return fmt.Errorf("[%s] Failed to authorize security group rule for '%s': %w", sgID, description, err)
			}
		} else {
			log.Printf("[%s] Successfully authorized rule for description '%s' with IP %s.\n", sgID, description, targetCidrIP)
		}
	}

	return nil
}

func main() {
	myName := flag.String("my-name", "", "Name of the host to resolve")
	profileName := flag.String("profile", "default", "AWS profile name from credentials")
	sgIDsRaw := flag.String("sg-id", "", "Comma-separated list of target Security Group IDs")
	sgTagNamesRaw := flag.String("sg-tag-name", "", "Comma-separated list of target Security Group Tag 'Name' values")

	flag.Parse()

	if *myName == "" {
		fmt.Println("Error: --my-name is required")
		flag.Usage()
		os.Exit(1)
	}

	if *sgIDsRaw == "" && *sgTagNamesRaw == "" {
		log.Println("Error: You must provide at least one Security Group identifier via --sg-id or --sg-tag-name.")
		flag.Usage()
		os.Exit(1)
	}

	if *sgIDsRaw != "" && *sgTagNamesRaw != "" {
		log.Println("Error: Please use either --sg-id OR --sg-tag-name, not both.")
		flag.Usage()
		os.Exit(1)
	}

	var sgIDs []string
	var sgTagNames []string

	if *sgIDsRaw != "" {
		sgIDs = strings.Split(*sgIDsRaw, ",")

		for i := range sgIDs {
			sgIDs[i] = strings.TrimSpace(sgIDs[i])
		}

		cleanedIDs := []string{}

		for _, id := range sgIDs {
			if id != "" {
				cleanedIDs = append(cleanedIDs, id)
			}
		}

		sgIDs = cleanedIDs

		if len(sgIDs) == 0 {
			log.Fatal("Error: --sg-id flag provided but contained no valid IDs after parsing.")
		}
	} else {
		sgTagNames = strings.Split(*sgTagNamesRaw, ",")

		for i := range sgTagNames {
			sgTagNames[i] = strings.TrimSpace(sgTagNames[i])
		}

		cleanedTags := []string{}

		for _, tag := range sgTagNames {
			if tag != "" {
				cleanedTags = append(cleanedTags, tag)
			}
		}

		sgTagNames = cleanedTags

		if len(sgTagNames) == 0 {
			log.Fatal("Error: --sg-tag-name flag provided but contained no valid tag names after parsing.")
		}
	}

	publicIP, err := getPublicIP()
	if err != nil {
		log.Fatalf("Error getting public IP: %v", err)
	}

	ctx := context.TODO()
	awsCfg, err := loadAWSConfig(ctx, *profileName)
	if err != nil {
		log.Fatalf("Error loading AWS config: %v", err)
	}

	ec2Client := ec2.NewFromConfig(awsCfg)

	log.Println("Resolving and validating target Security Group(s)...")

	finalSgIDs, err := findSecurityGroupIDs(ctx, ec2Client, sgIDs, sgTagNames)
	if err != nil {
		log.Fatalf("Error resolving Security Group identifiers: %v", err)
	}

	if len(finalSgIDs) == 0 {
		log.Fatalf("No valid Security Groups found or resolved. Exiting.")
	}

	log.Printf("Resolved %d unique Security Group ID(s) to process: %v", len(finalSgIDs), finalSgIDs)

	log.Printf("Starting rule sync process for %d Security Group(s)...", len(finalSgIDs))

	var wg sync.WaitGroup
	errorChannel := make(chan error, len(finalSgIDs))
	successCount := 0
	var successMu sync.Mutex

	for _, sgID := range finalSgIDs {
		wg.Add(1)

		go func(currentSgID string) {
			defer wg.Done()

			log.Printf("[%s] Starting sync...", currentSgID)

			err := syncSecurityGroupRule(ctx, ec2Client, currentSgID, publicIP, *myName)
			if err != nil {
				log.Printf("[%s] Error syncing rule: %v", currentSgID, err)
				errorChannel <- fmt.Errorf("[%s] %w", currentSgID, err)
			} else {
				log.Printf("[%s] Sync completed successfully.", currentSgID)
				successMu.Lock()
				successCount++
				successMu.Unlock()
			}
		}(sgID)
	}

	wg.Wait()

	close(errorChannel)

	var syncErrors []error

	for err := range errorChannel {
		syncErrors = append(syncErrors, err)
	}

	fmt.Println("-----------------------------------------------------------------------------------")
	fmt.Println("Sync Process Summary:")
	fmt.Printf("  Allowed TCP traffic from: %s/32\n", publicIP)
	fmt.Printf("  Rule description: %s\n", *myName)
	fmt.Printf("  Using AWS Profile: %s\n", *profileName)
	fmt.Printf("  Using AWS Region: %s\n", awsCfg.Region)
	fmt.Printf("  Total Security Groups Processed: %d\n", len(finalSgIDs))
	fmt.Printf("  Successfully Synced: %d\n", successCount)
	fmt.Printf("  Failed: %d\n", len(syncErrors))

	if len(syncErrors) > 0 {
		fmt.Println("  Errors Encountered:")
		for _, syncErr := range syncErrors {
			fmt.Printf("    - %v\n", syncErr)
		}
		fmt.Println("-----------------------------------------------------------------------------------")
		os.Exit(1)
	} else {
		fmt.Println("-----------------------------------------------------------------------------------")
		fmt.Println("✅ All specified Security Groups synced successfully.")
	}
}
