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
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

const (
	credentialsFile = ".aws/credentials"
)

// Work in progress to mock the STS Client calls...
// type StsApi interface {
// 	NewFromConfig(cfg aws.Config, optFns ...func(*sts.Options)) *sts.Client
// 	AssumeRoleWithSAML(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error)
// }

// The main login function - this orchestrations login and SAML verification
// then configures the AWS credentials file with the credentials returned by the
// AWS STS service.
func Login(cli types.CLI) {
	log := cli.Logger
	fmt.Println(types.Header)
	log.Info("Starting authentication...")
	setupCredentials(log)
	saml := saml.Saml{
		IdpEntryUrl: cli.IdpEntryUrl,
		Logger:      log,
	}
	saml.Verify()
	loginRole := prompts.RoleSelect(types.Roles)
	duration := int32(cli.Duration)

	awsSession, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion(cli.Region))
	stsClient := sts.NewFromConfig(awsSession)
	assumeRoleInput := sts.AssumeRoleWithSAMLInput{
		DurationSeconds: &duration,
		PrincipalArn:    &loginRole.PrincipalArn,
		RoleArn:         &loginRole.Name,
		SAMLAssertion:   &saml.Assertion,
	}

	creds, err := stsClient.AssumeRoleWithSAML(context.TODO(), &assumeRoleInput)
	utils.Check(err, "Error assuming role with SAML")

	content := writeCredentials(*creds, duration, cli.Profile, cli.Region)
	dirname, err := os.UserHomeDir()
	utils.Check(err, "Error locating user home directory...")
	credFilePath := dirname + credentialsFile
	f, _ := os.Create(credFilePath)
	defer f.Close()
	f.Write([]byte(content))
}

// Configures the user's username and password by first checking command line flags
// then checking for environment variables, and finally prompting the user directly
func setupCredentials(logger *logrus.Logger) {
	if types.LoginUser.Username == "" {
		logger.Debug("Login username not set via command line flags, checking environment variables...")
		user, exists := os.LookupEnv("AWS_USERNAME")
		if !exists {
			logger.Debug("Unable to locate AWS_USERNAME environment variable, prompting user...")
			user = prompts.Username()
		}
		types.LoginUser.Username = user
	} else {
		logger.Info("Login username provided via CLI flags.")
	}

	if types.LoginUser.Password == "" {
		logger.Debug("Login password not set via command line flags, checking environment variables...")
		pass, exists := os.LookupEnv("AWS_PASSWORD")
		if !exists {
			logger.Debug("Unable to locate AWS_PASSWORD environment variable, prompting user...")
			pass = prompts.Password()
		}
		types.LoginUser.Password = pass
	} else {
		logger.Info("Login password set via CLI flags.")
	}

	if types.LoginUser.Domain == "" {
		logger.Debug("Login domain not set via command line flags, checking environment variables...")
		domain, exists := os.LookupEnv("ADFS_DOMAIN")
		if !exists {
			logger.Debug("Unable to locate ADFS_DOMAIN environment variable, prompting user...")
			domain = prompts.Domain()
		}
		types.LoginUser.Domain = domain
	} else {
		logger.Info("Login ADFS domain set via CLI flags.")
	}
	logger.Debugf("Setup credentials --> Username: %s :: Password: %s :: Domain: %s\n", types.LoginUser.Username, types.LoginUser.Password, types.LoginUser.Domain)
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
