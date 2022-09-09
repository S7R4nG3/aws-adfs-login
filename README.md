# aws-adfs-login

A simple login tool that allows you to authenticate through Active Directory Federated Services to assume an AWS IAM role in your account.

## Installation

Simply download the latest version of the binary from the [Releases](https://github.com/S7R4nG3/aws-adfs-login/releases) page and put it in your PATH!

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

## License
 
The MIT License (MIT)

Copyright (c) 2015 Chris Kibble

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.