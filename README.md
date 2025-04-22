# aws-sg-updater
Updates an AWS Security Group Inbound Role with your public IP address

# Requirements
Configured AWS CLI

# Using multiple IDs
go run main.go --my-name="Rodrigo" --profile="ipaves" --sg-id="sg-01cde4f76755f5c05, sg-07f7956b1effd9336"

# Using multiple Tag Names
go run main.go --my-name="Rodrigo" --profile="xrm" --sg-tag-name="controlxrm-suporte-sg"