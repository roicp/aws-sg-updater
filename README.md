# aws-sg-updater
Updates an AWS Security Group Inbound Role with your public IP address

# Requirements
[AWS CLI get started](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

[AWS CLI setup](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html)


# Using multiple IDs
go run main.go --my-name="Rule description" --profile="AWS config profile" --sg-id="sg-1111111, sg-222222"

# Using multiple Tag Names
go run main.go --my-name="Rule description" --profile="AWS config profile" --sg-tag-name="sg-name-a, sg-name-b"

# Compilation
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o aws-sg-updater.exe .
Remove-Item Env:GOOS
Remove-Item Env:GOARCH
