package cmd

import (
	"fmt"
	"log"

	"github.com/sirupsen/logrus"

	"github.com/S7R4nG3/aws-adfs-login/auth"
	"github.com/S7R4nG3/aws-adfs-login/types"
	"github.com/spf13/cobra"
)

const (
	version  = "v0"
	cmdShort = "aws-adfs-login is a simple CLI tool to login to AWS via an ADFS portal"
	cmdLong  = `
This simple login utility provides an easy interface for end users to login.
Provide a few simple arguments/environment variables and you'll be off and rolling!`
)

var (
	debug   = false
	rootCmd = &cobra.Command{
		Use:   "aws-login",
		Short: cmdShort,
		Long:  cmdLong,
		Run: func(cmd *cobra.Command, args []string) {
			types.Cli.Logger = loggingConfig()
			auth.Login(types.Cli)
		},
	}
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Prints the login tool version.",
		Long:  "",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aws-login %s\n", version)
		},
	}
)

func init() {
	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging.")
	rootCmd.Flags().StringVarP(&types.Cli.Region, "region", "r", "", "The AWS region (required).")
	rootCmd.Flags().StringVarP(&types.Cli.IdpEntryUrl, "idpEntryUrl", "i", "", "The IDP Entry URL for your ADFS environment.")
	rootCmd.Flags().StringVarP(&types.Cli.CABundle, "ca-bundle", "", "", "Path to your CA bundle to authenticate with ADFS.")
	rootCmd.Flags().StringVarP(&types.Cli.Profile, "profile", "", "default", "The name of your AWS credentials profile.")
	rootCmd.Flags().IntVarP(&types.Cli.Duration, "duration", "", 900, "The duration of your STS credentials.")
	rootCmd.Flags().StringVarP(&types.LoginUser.Username, "username", "u", "", "Your login username")
	rootCmd.Flags().StringVarP(&types.LoginUser.Password, "password", "p", "", "Your login password - Please don't leave this in plaintext, use an environment variable...")
	rootCmd.Flags().StringVarP(&types.LoginUser.Domain, "domain", "", "", "Your login ADFS domain.")
	rootCmd.MarkFlagRequired("region")
	rootCmd.MarkFlagRequired("idpEntryUrl")
	rootCmd.AddCommand(versionCmd)
}

// Primary execution entrypoint for the CLI
func Execute() {
	rootCmd.Execute()
}

func loggingConfig() *logrus.Logger {
	logger := logrus.New()
	log.SetOutput(logger.Writer())
	logger.SetLevel(logrus.ErrorLevel)
	if debug {
		logger.SetLevel(logrus.DebugLevel)
	}
	return logger
}
