package saml

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/S7R4nG3/aws-adfs-login/types"
	"github.com/S7R4nG3/aws-adfs-login/utils"
	"github.com/sirupsen/logrus"
	"github.com/yhat/scrape"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type Saml struct {
	IdpEntryUrl     string
	CABundle        string
	LoginPage       LoginPage
	Assertion       string
	DecodedSaml     []byte
	SamlXMLResponse SamlXMLResponse
	Logger          *logrus.Logger
}

type LoginPage struct {
	ActionUrl string
	FormData  url.Values
}

type SamlXMLResponse struct {
	XMLName xml.Name       `xml:"Response"`
	Attrs   []XmlAttribute `xml:"Assertion>AttributeStatement>Attribute"`
}

type XmlAttribute struct {
	Name   string   `xml:"Name,attr"`
	Values []string `xml:"AttributeValue"`
}

// Primary entrypoint to begin SAML verification - this first accesses the login portal
// via the provided IDP Entry URL and identifies the Username, Password, and Submit fields.
// Next, it POSTs the contents of the user's login information to retrieve a SAML response.
// The response is then decoded and parsed to identify the AWS IAM roles that the user has access
// to assume, and these roles are written to a global types variable to be accessible by
// the end user prompts for selection of a specific role.
func (saml *Saml) Verify() {
	log := saml.Logger
	log.Info("Begin Saml request...")
	saml.portalLogin()
	log.Infof("Login portal parsed: %v", saml.LoginPage)
	saml.assertion()
	saml.DecodedSaml, _ = base64.StdEncoding.DecodeString(saml.Assertion)
	saml.parseSamlRoles()
	log.Info("Saml verification complete!")
}

// Orchestrations the login portal authentication with the provided username and
// password. the request URL and response are written back to the paren SAML struct
func (saml *Saml) portalLogin() {
	log := saml.Logger
	log.Info("Begin Portal login...")
	client := saml.newHttpClient()
	page, err := client.Get(saml.IdpEntryUrl)
	utils.Check(err, "Error in GET to login portal URL")
	defer page.Body.Close()
	root, err := html.Parse(page.Body)
	utils.Check(err, "Error parsing Login Portal HTML")

	inputs := scrape.FindAll(root, func(hn *html.Node) bool {
		return hn.DataAtom == atom.Input
	})
	form, _ := scrape.Find(root, func(hn *html.Node) bool {
		return hn.DataAtom == atom.Form
	})

	formData := url.Values{}
	userWithDomain := types.LoginUser.Domain + "\\" + types.LoginUser.Username

	for _, n := range inputs {
		name := scrape.Attr(n, "name")
		value := scrape.Attr(n, "value")
		switch {
		case strings.Contains(name, "Password"):
			formData.Set(name, types.LoginUser.Password)
		case strings.Contains(name, "Username"):
			formData.Set(name, userWithDomain)
		default:
			formData.Set(name, value)
		}
	}

	saml.LoginPage.ActionUrl = saml.IdpEntryUrl + scrape.Attr(form, "action")
	saml.LoginPage.FormData = formData
	log.Info("Portal login complete!")
}

// Configures retrieval of the SAML response from the login portal and returns this
// response back to the parent SAML struct.
func (saml *Saml) assertion() {
	log := saml.Logger
	log.Info("Starting SAML assertion parsing...")
	client := saml.newHttpClient()
	page, err := client.Post(saml.LoginPage.ActionUrl, "application/x-www-form-urlencoded", strings.NewReader(saml.LoginPage.FormData.Encode()))
	utils.Check(err, "Error with POST for SAML assertion")
	defer page.Body.Close()
	root, err := html.Parse(page.Body)
	utils.Check(err, "Error parsing SAML HTML response")
	input, ok := scrape.Find(root, func(hn *html.Node) bool {
		return hn.DataAtom == atom.Input && scrape.Attr(hn, "name") == "SAMLResponse"
	})
	if saml.Assertion == "" && ok {
		saml.Assertion = scrape.Attr(input, "value")
	}
	log.Info("SAML Assertion complete!")
}

// Parses the SAML assertion to retrieve the list of AWS IAM roles that the
// authenticated user has access to assume. These roles are written back to
// a global types variable to be accessible for user selection prompts.
func (saml *Saml) parseSamlRoles() {
	log := saml.Logger
	log.Info("Begin parsing AWS roles from SAML response...")
	err := xml.Unmarshal(saml.DecodedSaml, &saml.SamlXMLResponse)
	utils.Check(err, "Error unmarshalling SAML XML response")
	for _, attrs := range saml.SamlXMLResponse.Attrs {
		if attrs.Name == "https://aws.amazon.com/SAML/Attributes/Role" {
			for _, val := range attrs.Values {
				roleStr := strings.Split(val, ",")
				role := types.Role{
					Name:         roleStr[1],
					PrincipalArn: roleStr[0],
				}
				types.Roles = append(types.Roles, role)
			}
		}
	}
	log.Infof("Parsed Access Roles: %v", types.Roles)
	log.Info("Role parsing complete!")
}

// General purpose http Client configuration if users provide a
// CA bundle path.
func (saml *Saml) newHttpClient() *http.Client {
	client := &http.Client{}
	if saml.CABundle != "" {
		caCert, err := ioutil.ReadFile(saml.CABundle)
		utils.Check(err, "Error reading CA Bundle")
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}
	}
	return client
}
