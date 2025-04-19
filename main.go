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

func findSecurityGroupID(ctx context.Context, client *ec2.Client, sgID string, sgTagName string) (string, error) {
	if sgID != "" {
		log.Printf("Verifying provided Security Group ID: %s\n", sgID)

		input := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []string{sgID},
		}

		_, err := client.DescribeSecurityGroups(ctx, input)

		if err != nil {
			var apiErr *smithy.GenericAPIError

			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidGroup.NotFound" {
				return "", fmt.Errorf("security group with ID '%s' not found", sgID)
			}

			return "", fmt.Errorf("failed to verify security group ID '%s': %w", sgID, err)
		}

		log.Printf("Security Group ID %s verified successfully.\n", sgID)

		return sgID, nil
	}

	if sgTagName != "" {
		log.Printf("Searching for Security Group with tag Name: %s\n", sgTagName)

		input := &ec2.DescribeSecurityGroupsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("tag:Name"),
					Values: []string{sgTagName},
				},
			},
		}

		result, err := client.DescribeSecurityGroups(ctx, input)

		if err != nil {
			return "", fmt.Errorf("failed to describe security groups with tag Name '%s': %w", sgTagName, err)
		}

		if len(result.SecurityGroups) == 0 {
			return "", fmt.Errorf("no security group found with tag Name: %s", sgTagName)
		}

		if len(result.SecurityGroups) > 1 {
			return "", fmt.Errorf("multiple security groups found with tag Name: %s. Please use --sg-id for specificity", sgTagName)
		}

		foundID := *result.SecurityGroups[0].GroupId

		log.Printf("Found Security Group ID by tag: %s\n", foundID)

		return foundID, nil
	}

	return "", fmt.Errorf("you must specify either --sg-id or --sg-tag-name")
}

func syncSecurityGroupRule(ctx context.Context, client *ec2.Client, sgID, publicIP, description string) error {
	targetCidrIP := publicIP + "/32"
	ruleNeedsUpdate := false
	ruleNeedsAdding := true
	var ruleToRevoke *types.IpPermission = nil

	log.Printf("Checking existing rules in SG %s for description '%s'\n", sgID, description)

	descInput := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	}

	sgDesc, err := client.DescribeSecurityGroups(ctx, descInput)
	if err != nil {
		var apiErr *smithy.GenericAPIError

		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidGroup.NotFound" {
			return fmt.Errorf("security group %s not found during rule sync", sgID)
		}

		return fmt.Errorf("failed to describe security group %s: %w", sgID, err)
	}

	if len(sgDesc.SecurityGroups) == 0 {
		return fmt.Errorf("security group %s description returned empty list", sgID)
	}

	theGroup := sgDesc.SecurityGroups[0]

	for _, ipPerm := range theGroup.IpPermissions {
		if aws.ToString(ipPerm.IpProtocol) == "tcp" && aws.ToInt32(ipPerm.FromPort) == 0 && aws.ToInt32(ipPerm.ToPort) == 65535 {
			var rangesToRevoke []types.IpRange
			var rangesToKeep []types.IpRange

			for _, ipRange := range ipPerm.IpRanges {
				if aws.ToString(ipRange.Description) == description {
					if aws.ToString(ipRange.CidrIp) == targetCidrIP {
						log.Printf("Found existing rule for description '%s' with correct IP %s. No changes needed.\n", description, targetCidrIP)
						ruleNeedsAdding = false
						ruleNeedsUpdate = false
						rangesToKeep = append(rangesToKeep, ipRange)
						break
					} else {
						log.Printf("Found existing rule for description '%s' with outdated IP %s. Marking for removal.\n", description, aws.ToString(ipRange.CidrIp))
						ruleNeedsUpdate = true
						rangesToRevoke = append(rangesToRevoke, ipRange)
					}
				} else {
					rangesToKeep = append(rangesToKeep, ipRange)
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
		log.Printf("Revoking outdated rule(s) for description '%s'...\n", description)

		revokeInput := &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: []types.IpPermission{*ruleToRevoke},
		}

		_, err := client.RevokeSecurityGroupIngress(ctx, revokeInput)
		if err != nil {
			var apiErr *smithy.GenericAPIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidPermission.NotFound" {
				log.Printf("Warning: Rule to revoke was not found (maybe already deleted): %v\n", err)
			} else {
				return fmt.Errorf("failed to revoke old security group rule for '%s': %w", description, err)
			}
		} else {
			log.Printf("Successfully revoked outdated rule(s) for description '%s'.\n", description)
		}
	}

	if ruleNeedsAdding && ruleNeedsUpdate {
		log.Printf("Authorizing new rule for description '%s' with IP %s...\n", description, targetCidrIP)

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
				log.Printf("Rule for %s already exists (possibly added concurrently or revoke failed silently). No changes needed.\n", targetCidrIP)
			} else {
				return fmt.Errorf("failed to authorize new security group rule for '%s': %w", description, err)
			}
		} else {
			log.Printf("Successfully authorized new rule for description '%s' with IP %s.\n", description, targetCidrIP)
		}
	} else if ruleNeedsAdding && !ruleNeedsUpdate {
		log.Printf("No rule found for description '%s'. Authorizing new rule with IP %s...\n", description, targetCidrIP)

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
				log.Printf("Rule for %s already exists (possibly added concurrently). No changes needed.\n", targetCidrIP)
			} else {
				return fmt.Errorf("failed to authorize new security group rule for '%s': %w", description, err)
			}
		} else {
			log.Printf("Successfully authorized new rule for description '%s' with IP %s.\n", description, targetCidrIP)
		}
	}

	return nil
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
	targetSgTagName := *sgTagName

	if targetSgId == "" && targetSgTagName == "" {
		fmt.Println("Neither --sg-id nor --sg-tag-name provided")
		flag.Usage()
		os.Exit(1)
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

	finalSgID, err := findSecurityGroupID(ctx, ec2Client, targetSgId, targetSgTagName)
	if err != nil {
		log.Fatalf("Error finding Security Group: %v", err)
	}

	err = syncSecurityGroupRule(ctx, ec2Client, finalSgID, publicIP, *myName)
	if err != nil {
		log.Fatalf("Error updating security group rule: %v", err)
	}

	fmt.Println("---------------------------------------------------------------")
	fmt.Printf("✅ Successfully updated Security Group %s\n", finalSgID)
	fmt.Printf("   Allowed TCP traffic from: %s/32\n", publicIP)
	fmt.Printf("   Rule description: %s\n", *myName)
	fmt.Printf("   Using AWS Profile: %s\n", *profileName)
	fmt.Printf("   Using AWS Region: %s\n", awsCfg.Region)
	fmt.Println("---------------------------------------------------------------")
}
