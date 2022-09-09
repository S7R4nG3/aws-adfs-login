package auth

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/S7R4nG3/aws-adfs-login/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/sirupsen/logrus"
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

type mockStsClient func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error)

func (m mockStsClient) AssumeRoleWithSAML(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
	return m(ctx, params, optFns...)
}

func Test_Login(t *testing.T) {
	accessKeyId := "someaccesskeyid"
	secretAccessKey := "somesecretaccesskey"
	sessionToken := "somesessiontoken"
	var expiration time.Time

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
		name      string
		stsclient func() StsApi
		input     CLI
	}{
		{
			name: "Validate login functions...",
			stsclient: func() StsApi {
				return mockStsClient(
					func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
						expiration = time.Now().Local().Add(time.Hour + time.Minute + time.Second*time.Duration(int64(*params.DurationSeconds)))
						return &sts.AssumeRoleWithSAMLOutput{
							Credentials: &stsTypes.Credentials{
								AccessKeyId:     &accessKeyId,
								SecretAccessKey: &secretAccessKey,
								SessionToken:    &sessionToken,
								Expiration:      &expiration,
							},
						}, nil
					})
			},
			input: CLI{
				IdpEntryUrl: server.URL,
				Region:      "us-east-1",
				Duration:    900,
				Profile:     "default",
				AWSRole: types.Role{
					Name:         "arn:aws:iam::123456789123:role/AdministratorAccess",
					PrincipalArn: "arn:aws:iam::123456789123:saml-provider/ADFS",
				},
				Logger: logrus.New(),
			},
		},
	}

	for _, tt := range tests {
		t.Logf("Running test -- %s", tt.name)
		tt.input.StsClient = tt.stsclient()
		types.LoginUser.Username = "potato"
		types.LoginUser.Password = "cheese"
		types.LoginUser.Domain = "domain"
		tt.input.Login()
	}
}

func Test_STS_Credentails(t *testing.T) {
	accessKeyId := "someaccesskeyid"
	secretAccessKey := "somesecretaccesskey"
	sessionToken := "somesessiontoken"
	var expiration time.Time
	tests := []struct {
		name   string
		client func() StsApi
		input  CLI
		want   sts.AssumeRoleWithSAMLOutput
	}{
		{
			name: "Validate STS Credentials",
			client: func() StsApi {
				return mockStsClient(
					func(ctx context.Context, params *sts.AssumeRoleWithSAMLInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithSAMLOutput, error) {
						expiration = time.Now().Local().Add(time.Hour + time.Minute + time.Second*time.Duration(int64(*params.DurationSeconds)))
						return &sts.AssumeRoleWithSAMLOutput{
							Credentials: &stsTypes.Credentials{
								AccessKeyId:     &accessKeyId,
								SecretAccessKey: &secretAccessKey,
								SessionToken:    &sessionToken,
								Expiration:      &expiration,
							},
						}, nil
					})
			},
			input: CLI{
				Duration: 900,
				AWSRole: types.Role{
					Name:         "arn:aws:iam::123456789123:role/LocalAdmin",
					PrincipalArn: "arn:aws:iam::123456789123:saml-provider/ADFS",
				},
				Logger: logrus.New(),
			},
			want: sts.AssumeRoleWithSAMLOutput{
				Credentials: &stsTypes.Credentials{
					AccessKeyId:     &accessKeyId,
					SecretAccessKey: &secretAccessKey,
					SessionToken:    &sessionToken,
					Expiration:      &expiration,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Logf("Running test -- %s", tt.name)
		tt.input.StsClient = tt.client()
		duration := int32(tt.input.Duration)
		got := tt.input.getStsCredentials(duration, "")
		t.Logf("Retreived temporary STS credentials -- AccessKeyID: %v -- SecretAccessKey: %v -- SessionToken: %v -- Expiration: %v", getPointerValue(got.Credentials.AccessKeyId), getPointerValue(got.Credentials.SecretAccessKey), getPointerValue(got.Credentials.SessionToken), got.Credentials.Expiration)
		if !reflect.DeepEqual(got.Credentials, tt.want.Credentials) {
			t.Errorf("Error running test -- got: %v want: %v", got, tt.want)
		}
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
