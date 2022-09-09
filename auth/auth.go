package auth

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"text/template"

	"github.com/S7R4nG3/aws-adfs-login/prompts"
	"github.com/S7R4nG3/aws-adfs-login/saml"
	"github.com/S7R4nG3/aws-adfs-login/types"
	"github.com/S7R4nG3/aws-adfs-login/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

const (
	credentialsFile = ".aws/credentials"
)

// Work in progress to mock the STS Client calls...
type StsApi interface {
	AssumeRoleWithSAML(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error)
}

type StsNewConfig interface {
	NewFromConfig(cfg aws.Config, optFns ...func(*sts.Options)) *sts.Client
}

// A generic CLI struct used to contain the CLI flag values and shared logger
type CLI struct {
	Region      string
	Duration    int
	Profile     string
	IdpEntryUrl string
	CABundle    string
	AWSRole     types.Role
	StsClient   StsApi
	StsCreds    sts.AssumeRoleWithSAMLOutput
	Logger      *logrus.Logger
}

// The main login function - this orchestrations login and SAML verification
// then configures the AWS credentials file with the credentials returned by the
// AWS STS service.
func (cli CLI) Login() {
	log := cli.Logger
	fmt.Println(types.Header)
	log.Info("Starting authentication...")
	cli.setupCredentials()
	saml := saml.Saml{
		IdpEntryUrl: cli.IdpEntryUrl,
		Logger:      log,
	}
	saml.Verify()
	if cli.AWSRole.Name == "" {
		cli.AWSRole = prompts.RoleSelect(types.Roles)
	}
	duration := int32(cli.Duration)
	if cli.StsClient == nil {
		awsSession, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion(cli.Region))
		cli.StsClient = sts.NewFromConfig(awsSession)
	}
	creds := cli.getStsCredentials(duration, saml.Assertion)
	content := writeCredentials(*creds, duration, cli.Profile, cli.Region)
	dirname, err := os.UserHomeDir()
	utils.Check(err, "Error locating user home directory...")
	credFilePath := dirname + credentialsFile
	f, _ := os.Create(credFilePath)
	defer f.Close()
	f.Write([]byte(content))
	log.Info("Login Complete!")
}

func (cli CLI) getStsCredentials(duration int32, samlAssertion string) *sts.AssumeRoleWithSAMLOutput {
	log := cli.Logger
	log.Infof("Begin STS Credentials retrieval...")
	assumeRoleInput := sts.AssumeRoleWithSAMLInput{
		DurationSeconds: &duration,
		PrincipalArn:    &cli.AWSRole.PrincipalArn,
		RoleArn:         &cli.AWSRole.Name,
		SAMLAssertion:   &samlAssertion,
	}

	creds, err := cli.StsClient.AssumeRoleWithSAML(context.TODO(), &assumeRoleInput)
	utils.Check(err, "Error retrieving AWS login content from STS")

	log.Infof("STS Credential retrieval complete!")
	return creds
}

// Configures the user's username and password by first checking command line flags
// then checking for environment variables, and finally prompting the user directly
func (cli CLI) setupCredentials() {
	log := cli.Logger
	if types.LoginUser.Username == "" {
		log.Debug("Login username not set via command line flags, checking environment variables...")
		user, exists := os.LookupEnv("AWS_USERNAME")
		if !exists {
			log.Debug("Unable to locate AWS_USERNAME environment variable, prompting user...")
			user = prompts.Username()
		}
		types.LoginUser.Username = user
	} else {
		log.Info("Login username provided via CLI flags.")
	}

	if types.LoginUser.Password == "" {
		log.Debug("Login password not set via command line flags, checking environment variables...")
		pass, exists := os.LookupEnv("AWS_PASSWORD")
		if !exists {
			log.Debug("Unable to locate AWS_PASSWORD environment variable, prompting user...")
			pass = prompts.Password()
		}
		types.LoginUser.Password = pass
	} else {
		log.Info("Login password set via CLI flags.")
	}

	if types.LoginUser.Domain == "" {
		log.Debug("Login domain not set via command line flags, checking environment variables...")
		domain, exists := os.LookupEnv("ADFS_DOMAIN")
		if !exists {
			log.Debug("Unable to locate ADFS_DOMAIN environment variable, prompting user...")
			domain = prompts.Domain()
		}
		types.LoginUser.Domain = domain
	} else {
		log.Info("Login ADFS domain set via CLI flags.")
	}
	log.Debugf("Setup credentials --> Username: %s :: Password: %s :: Domain: %s\n", types.LoginUser.Username, types.LoginUser.Password, types.LoginUser.Domain)
}

// Configurations the credentials file string to ensure the file is properly formatted with the
// generated keys to the correct profile and region
func writeCredentials(creds sts.AssumeRoleWithSAMLOutput, duration int32, profile string, region string) string {
	strTempl := `
[{{ .Profile }}]
region={{ .Region }}
aws_access_key_id={{ .AccessKey }}
aws_secret_access_key={{ .SecretAccessKey }}
aws_session_token={{ .SessionToken }}`
	templ := template.New("creds")
	templ, _ = templ.Parse(strTempl)
	var buf bytes.Buffer
	templ.Execute(&buf, struct {
		Profile         string
		Region          string
		AccessKey       string
		SecretAccessKey string
		SessionToken    string
	}{
		Profile:         profile,
		Region:          region,
		AccessKey:       *creds.Credentials.AccessKeyId,
		SecretAccessKey: *creds.Credentials.SecretAccessKey,
		SessionToken:    *creds.Credentials.SessionToken,
	})
	return buf.String()
}

func getPointerValue(p *string) string {
	if p != nil {
		return *p
	}
	return ""
}
