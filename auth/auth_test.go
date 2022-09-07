package auth

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/S7R4nG3/aws-adfs-login/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

const (
	testLoginPage    = "../tests/login-page.html"
	testLoginSuccess = "../tests/login-success.html"
	testSamlResponse = "../tests/saml-response.xml"
)

type creds struct {
	accesskeyid     string
	secretaccesskey string
	sessiontoken    string
}

func Test_Login(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			testBody, _ := ioutil.ReadFile(testLoginPage)
			rw.Write(testBody)
		} else {
			testBody, _ := ioutil.ReadFile(testLoginSuccess)
			rw.Write(testBody)
		}
	})
	mux.HandleFunc("/adfs/ls/?SAMLRequest=REQUEST", func(rw http.ResponseWriter, req *http.Request) {

	})
	server := httptest.NewServer(mux)
	defer server.Close()

	tests := []struct {
		name  string
		input types.CLI
		want  string
	}{
		// Work in progress - need to mock the STS Client AWS calls before re-enabling
		// {
		// 	name: "Validate login functions...",
		// 	input: types.CLI{
		// 		Region:   "us-east-1",
		// 		Duration: 900,
		// 		Profile:  "default",
		// 		Logger:   logrus.New(),
		// 	},
		// 	want: "",
		// },
	}

	for _, tt := range tests {
		t.Logf("Running test -- %s", tt.name)
		types.LoginUser.Username = "potato"
		types.LoginUser.Password = "cheese"
		types.LoginUser.Domain = "domain"
		tt.input.IdpEntryUrl = server.URL
		Login(tt.input)
	}
}

func Test_Credential_Template(t *testing.T) {
	tests := []struct {
		name     string
		creds    creds
		profile  string
		region   string
		duration int
		want     string
	}{
		{
			name:     "Validate credentials template.",
			profile:  "saml",
			region:   "us-east-1",
			duration: 3600,
			creds: creds{
				accesskeyid:     "someaccesskeycontent",
				secretaccesskey: "secretaccesskeycontent",
				sessiontoken:    "anicesessiontoken",
			},
			want: `
[saml]
region=us-east-1
aws_access_key_id=someaccesskeycontent
aws_secret_access_key=secretaccesskeycontent
aws_session_token=anicesessiontoken`,
		},
	}

	for _, tt := range tests {
		t.Logf("Running test -- %s", tt.name)
		output := sts.AssumeRoleWithSAMLOutput{
			Credentials: &stsTypes.Credentials{
				AccessKeyId:     &tt.creds.accesskeyid,
				SecretAccessKey: &tt.creds.secretaccesskey,
				SessionToken:    &tt.creds.sessiontoken,
			},
		}
		duration := int32(tt.duration)
		got := writeCredentials(output, duration, tt.profile, tt.region)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Error in test -- got: %v want: %v", got, tt.want)
		}
	}
}
