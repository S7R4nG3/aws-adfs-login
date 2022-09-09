package types

const (
	Header = `
 █████  ██     ██ ███████      █████  ██████  ███████ ███████     ██       ██████   ██████  ██ ███    ██ 
██   ██ ██     ██ ██          ██   ██ ██   ██ ██      ██          ██      ██    ██ ██       ██ ████   ██ 
███████ ██  █  ██ ███████     ███████ ██   ██ █████   ███████     ██      ██    ██ ██   ███ ██ ██ ██  ██ 
██   ██ ██ ███ ██      ██     ██   ██ ██   ██ ██           ██     ██      ██    ██ ██    ██ ██ ██  ██ ██ 
██   ██  ███ ███  ███████     ██   ██ ██████  ██      ███████     ███████  ██████   ██████  ██ ██   ████`
)

// A global User variable used to contain the user login credentials
// so they can be provided via CLI flags or via direct user prompts.
var LoginUser User

// A global Role slice that contains a list of all available AWS IAM roles
// that an authenticated user has the ability to assume. This is used to
// be easily passed into a user selection prompt to select a particular
// role to login.
var Roles []Role

// A generic User struct used to contain user login credentials
type User struct {
	Username string
	Password string
	Domain   string
}

// A generic Role struct used to contain an AWS IAM role and its principal ARN.
type Role struct {
	Name         string
	PrincipalArn string
}
