package types

import (
	"github.com/sirupsen/logrus"
)

const (
	Header = `
 █████  ██     ██ ███████      █████  ██████  ███████ ███████     ██       ██████   ██████  ██ ███    ██ 
██   ██ ██     ██ ██          ██   ██ ██   ██ ██      ██          ██      ██    ██ ██       ██ ████   ██ 
███████ ██  █  ██ ███████     ███████ ██   ██ █████   ███████     ██      ██    ██ ██   ███ ██ ██ ██  ██ 
██   ██ ██ ███ ██      ██     ██   ██ ██   ██ ██           ██     ██      ██    ██ ██    ██ ██ ██  ██ ██ 
██   ██  ███ ███  ███████     ██   ██ ██████  ██      ███████     ███████  ██████   ██████  ██ ██   ████`
)

// Setup a LoginUser and Cli variable to be exported and accessible from all packages
var LoginUser User
var Cli CLI
var Roles []Role

type User struct {
	Username string
	Password string
	Domain   string
}

type CLI struct {
	Region      string
	Duration    int
	Profile     string
	IdpEntryUrl string
	CABundle    string
	Logger      *logrus.Logger
}

type Role struct {
	Name         string
	PrincipalArn string
}
