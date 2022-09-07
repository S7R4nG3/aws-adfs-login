package prompts

import (
	"errors"
	"fmt"
	"strings"

	"github.com/S7R4nG3/aws-adfs-login/types"
	"github.com/S7R4nG3/aws-adfs-login/utils"
	"github.com/manifoldco/promptui"
)

var (
	minimumUsernameLength = 6
	minimumPasswordLength = 6
	minimumDomainLength   = 6
)

func Username() string {
	validate := func(input string) error {
		if len(input) < minimumUsernameLength {
			errStr := "username cannot be shorter than " + fmt.Sprint(minimumUsernameLength) + " characters"
			return errors.New(errStr)
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "Username: ",
		Validate: validate,
	}

	username, err := prompt.Run()
	utils.Check(err, "Error prompting for username")

	return username
}

func Password() string {
	validate := func(input string) error {
		if len(input) < minimumPasswordLength {
			errStr := "password cannot be shorter than " + fmt.Sprint(minimumPasswordLength) + " characters"
			return errors.New(errStr)
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "Password: ",
		Validate: validate,
		Mask:     '*',
	}

	password, err := prompt.Run()
	utils.Check(err, "Error prompting for password")

	return password
}

func Domain() string {
	validate := func(input string) error {
		if len(input) < minimumDomainLength {
			errStr := "domain cannot be shorter than " + fmt.Sprint(minimumDomainLength) + " characters"
			return errors.New(errStr)
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "Domain: ",
		Validate: validate,
	}

	domain, err := prompt.Run()
	utils.Check(err, "Error prompting for domain")

	return domain
}

func RoleSelect(roles []types.Role) types.Role {
	templates := &promptui.SelectTemplates{
		Label:    "{{ .Name }}?",
		Active:   "☁️ {{ .Name | cyan }}",
		Inactive: "  {{ .Name }}",
		Selected: "✅ {{ .Name | green }}",
		Details:  `AWS Access Role -- {{ .Name }}`,
	}

	searcher := func(input string, index int) bool {
		role := roles[index]
		return strings.Contains(role.Name, input)
	}

	prompt := promptui.Select{
		Label:     "Access Role",
		Items:     roles,
		Templates: templates,
		Size:      4,
		Searcher:  searcher,
	}

	i, _, _ := prompt.Run()
	return roles[i]
}
