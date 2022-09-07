# aws-adfs-login

A simple login tool that allows you to authenticate through Active Directory Federated Services to assume an AWS IAM role in your account.

## Installation

Simply download the latest version of the binary from the [Releases]() page and put it in your PATH!

## General Usage

You can use the utility by executing `aws-login` with the required `--idpEntryUrl` and `--region` flags:

```bash
aws-login --idpEntryUrl "https://my-fancy-adfs-portal.com" --region "us-east-1"
```

Username, Password, and Domain prompts will request user input if the CLI flags are not present:

```bash
aws-login --idpEntryUrl "https://my-fancy-adfs-portal.com" --region "us-east-1" --username "john.stamos" --password $PASSWORD --domain "example.com"
```

or using environment variables:

```bash
export AWS_USERNAME="john.stamos"
export AWS_PASSWORD="somepassword"
export ADFS_DOMAIN="example.com"

aws-login --idpEntryUrl "https://my-fancy-adfs-portal.com" --region "us-east-1"
```



