package saml

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/S7R4nG3/aws-adfs-login/types"
	"github.com/sirupsen/logrus"
)

const (
	testLoginPage    = "../tests/login-page.html"
	testLoginSuccess = "../tests/login-success.html"
	testSamlResponse = "../tests/saml-response.xml"
)

func Test_Verify(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			testLoginBody, _ := os.ReadFile(testLoginPage)
			rw.Write(testLoginBody)
		} else {
			testLoginSuccess, _ := os.ReadFile(testLoginSuccess)
			rw.Write(testLoginSuccess)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	tests := []struct {
		name  string
		input Saml
		want  []types.Role
	}{
		{
			name: "Test Saml Verify",
			input: Saml{
				IdpEntryUrl: server.URL,
				Logger:      logrus.New(),
			},
			want: []types.Role{
				{
					Name:         "arn:aws:iam::123456789123:role/AdministratorAccess",
					PrincipalArn: "arn:aws:iam::123456789123:saml-provider/ADFS",
				},
				{
					Name:         "arn:aws:iam::987654321321:role/DeveloperAccess",
					PrincipalArn: "arn:aws:iam::987654321321:saml-provider/ADFS",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Logf("Running test -- %s", tt.name)
		tt.input.Verify()
		if !reflect.DeepEqual(types.Roles, tt.want) {
			t.Errorf("Error running test -- got: %v want: %v", types.Roles, tt.want)
		}
	}
}

func Test_ADFS_Portal_Login(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		testBody, _ := os.ReadFile(testLoginPage)
		rw.Write(testBody)
	}))
	defer server.Close()

	tests := []struct {
		name string
		user types.User
		want url.Values
	}{
		{
			name: "Validate the login form data parsing is correct",
			user: types.User{
				Username: "potato",
				Password: "cheese",
				Domain:   "domain",
			},
			want: url.Values{
				"__VIEWSTATE":          []string{"someviewstatedata"},
				"__VIEWSTATEGENERATOR": []string{"someviewstategeneratordata"},
				"__EVENTVALIDATION":    []string{"someeventvalidationdata"},
				"__db":                 []string{"15"},
				"ctl00$ContentPlaceHolder1$UsernameTextBox": []string{"domain\\potato"},
				"ctl00$ContentPlaceHolder1$PasswordTextBox": []string{"cheese"},
				"ctl00$ContentPlaceHolder1$SubmitButton":    []string{"Sign In"},
			},
		},
	}

	for _, tt := range tests {
		t.Logf("Running test -- %s", tt.name)
		types.LoginUser = tt.user
		mfa := Saml{
			IdpEntryUrl: server.URL,
			Logger:      logrus.New(),
		}
		mfa.portalLogin()
		got := mfa.LoginPage.FormData
		t.Logf("Login Form Data: %v", got)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Error running test -- got: %v want: %v", got, tt.want)
		}
	}
}

func Test_SAML_Assertion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		testBody, _ := os.ReadFile(testLoginSuccess)
		rw.Write(testBody)
	}))
	defer server.Close()

	tests := []struct {
		name     string
		formdata url.Values
		want     string
	}{
		{
			name: "Validate the SAML response is being parsed accurately",
			formdata: url.Values{
				"__VIEWSTATE":          []string{"someviewstatedata"},
				"__VIEWSTATEGENERATOR": []string{"someviewstategeneratordata"},
				"__EVENTVALIDATION":    []string{"someeventvalidationdata"},
				"__db":                 []string{"15"},
				"ctl00$ContentPlaceHolder1$UsernameTextBox": []string{"potato@domain"},
				"ctl00$ContentPlaceHolder1$PasswordTextBox": []string{"cheese"},
				"ctl00$ContentPlaceHolder1$SubmitButton":    []string{"Sign In"},
			},
			want: "PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iXzg3YTEzMjk1LTQ3NWItNGRkZS04ZDdjLTk1YjAyZDEyYmZhOCIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTAtMDhUMDU6NDA6NDEuOTAyWiIgRGVzdGluYXRpb249Imh0dHBzOi8vc2lnbmluLmF3cy5hbWF6b24uY29tL3NhbWwiIENvbnNlbnQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjb25zZW50OnVuc3BlY2lmaWVkIj4KICA8SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwOi8vYWRmcy5leGFtcGxlL2FkZnMvc2VydmljZXMvdHJ1c3Q8L0lzc3Vlcj4KICA8c2FtbHA6U3RhdHVzPgogICAgPHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPgogIDwvc2FtbHA6U3RhdHVzPgogIDxBc3NlcnRpb24geG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfNDgzZjNiNGItNzJjMC00YWRjLTlhZTUtZDkyMWI1YmMxOTQxIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTAtMDhUMDU6NDA6NDEuOTAyWiIgVmVyc2lvbj0iMi4wIj4KICAgIDxJc3N1ZXI+aHR0cDovL2FkZnMuZXhhbXBsZS9hZGZzL3NlcnZpY2VzL3RydXN0PC9Jc3N1ZXI+CiAgICA8ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4KICAgICAgPGRzOlNpZ25lZEluZm8+CiAgICAgICAgPGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgICAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+CiAgICAgICAgPGRzOlJlZmVyZW5jZSBVUkk9IiNfNDgzZjNiNGItNzJjMC00YWRjLTlhZTUtZDkyMWI1YmMxOTQxIj4KICAgICAgICAgIDxkczpUcmFuc2Zvcm1zPgogICAgICAgICAgICA8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4KICAgICAgICAgICAgPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgogICAgICAgICAgPC9kczpUcmFuc2Zvcm1zPgogICAgICAgICAgPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+CiAgICAgICAgICA8ZHM6RGlnZXN0VmFsdWU+RElHRVNUPC9kczpEaWdlc3RWYWx1ZT4KICAgICAgICA8L2RzOlJlZmVyZW5jZT4KICAgICAgPC9kczpTaWduZWRJbmZvPgogICAgICA8ZHM6U2lnbmF0dXJlVmFsdWU+U0lHTkFUVVJFPC9kczpTaWduYXR1cmVWYWx1ZT4KICAgICAgPEtleUluZm8geG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgogICAgICAgIDxkczpYNTA5RGF0YT4KICAgICAgICAgIDxkczpYNTA5Q2VydGlmaWNhdGU+Q0VSVElGSUNBVEU8L2RzOlg1MDlDZXJ0aWZpY2F0ZT4KICAgICAgICA8L2RzOlg1MDlEYXRhPgogICAgICA8L0tleUluZm8+CiAgICA8L2RzOlNpZ25hdHVyZT4KICAgIDxTdWJqZWN0PgogICAgICA8TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6cGVyc2lzdGVudCI+cG90YXRvQGRvbWFpbjwvTmFtZUlEPgogICAgICA8U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPgogICAgICAgIDxTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTYtMTAtMDhUMDU6NDU6NDEuOTAyWiIgUmVjaXBpZW50PSJodHRwczovL3NpZ25pbi5hd3MuYW1hem9uLmNvbS9zYW1sIi8+CiAgICAgIDwvU3ViamVjdENvbmZpcm1hdGlvbj4KICAgIDwvU3ViamVjdD4KICAgIDxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0xMC0wOFQwNTo0MDo0MS44ODZaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMTAtMDhUMDY6NDA6NDEuODg2WiI+CiAgICAgIDxBdWRpZW5jZVJlc3RyaWN0aW9uPgogICAgICAgIDxBdWRpZW5jZT51cm46YW1hem9uOndlYnNlcnZpY2VzPC9BdWRpZW5jZT4KICAgICAgPC9BdWRpZW5jZVJlc3RyaWN0aW9uPgogICAgPC9Db25kaXRpb25zPgogICAgPEF0dHJpYnV0ZVN0YXRlbWVudD4KICAgICAgPEF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiPgogICAgICAgIDxBdHRyaWJ1dGVWYWx1ZT5Kb2huU3RhbW9zPC9BdHRyaWJ1dGVWYWx1ZT4KICAgICAgPC9BdHRyaWJ1dGU+CiAgICAgIDxBdHRyaWJ1dGUgTmFtZT0iaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS9TQU1ML0F0dHJpYnV0ZXMvUm9sZSI+CiAgICAgICAgPEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjoxMjM0NTY3ODkxMjM6c2FtbC1wcm92aWRlci9BREZTLGFybjphd3M6aWFtOjoxMjM0NTY3ODkxMjM6cm9sZS9BZG1pbmlzdHJhdG9yQWNjZXNzPC9BdHRyaWJ1dGVWYWx1ZT4KICAgICAgICA8QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06Ojk4NzY1NDMyMTMyMTpzYW1sLXByb3ZpZGVyL0FERlMsYXJuOmF3czppYW06Ojk4NzY1NDMyMTMyMTpyb2xlL0RldmVsb3BlckFjY2VzczwvQXR0cmlidXRlVmFsdWU+CiAgICAgIDwvQXR0cmlidXRlPgogICAgICA8QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+CiAgICAgICAgPEF0dHJpYnV0ZVZhbHVlPjM2MDA8L0F0dHJpYnV0ZVZhbHVlPgogICAgICA8L0F0dHJpYnV0ZT4KICAgIDwvQXR0cmlidXRlU3RhdGVtZW50PgogICAgPEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0xMC0wOFQwNTo0MDo0MS41NTlaIiBTZXNzaW9uSW5kZXg9Il80ODNmM2I0Yi03MmMwLTRhZGMtOWFlNS1kOTIxYjViYzE5NDEiPgogICAgICA8QXV0aG5Db250ZXh0PgogICAgICAgIDxBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvQXV0aG5Db250ZXh0Q2xhc3NSZWY+CiAgICAgIDwvQXV0aG5Db250ZXh0PgogICAgPC9BdXRoblN0YXRlbWVudD4KICA8L0Fzc2VydGlvbj4KPC9zYW1scDpSZXNwb25zZT4=",
		},
	}

	for _, tt := range tests {
		t.Logf("Running test -- %s", tt.name)
		mfa := Saml{
			IdpEntryUrl: server.URL,
			LoginPage: LoginPage{
				ActionUrl: server.URL + "/adfs/ls/?SAMLRequest=REQUEST",
				FormData:  tt.formdata,
			},
			Logger: logrus.New(),
		}
		mfa.assertion()
		got := mfa.Assertion
		t.Logf("Saml Assertion: %s", got)
		if got != tt.want {
			t.Errorf("Error running test -- got: %v want: %v", got, tt.want)
		}
	}
}

func Test_Saml_Role_Parsing(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []types.Role
	}{
		{
			name:  "Validate AWS role parsing",
			input: "PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iXzg3YTEzMjk1LTQ3NWItNGRkZS04ZDdjLTk1YjAyZDEyYmZhOCIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTAtMDhUMDU6NDA6NDEuOTAyWiIgRGVzdGluYXRpb249Imh0dHBzOi8vc2lnbmluLmF3cy5hbWF6b24uY29tL3NhbWwiIENvbnNlbnQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjb25zZW50OnVuc3BlY2lmaWVkIj4KICA8SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwOi8vYWRmcy5leGFtcGxlL2FkZnMvc2VydmljZXMvdHJ1c3Q8L0lzc3Vlcj4KICA8c2FtbHA6U3RhdHVzPgogICAgPHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPgogIDwvc2FtbHA6U3RhdHVzPgogIDxBc3NlcnRpb24geG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfNDgzZjNiNGItNzJjMC00YWRjLTlhZTUtZDkyMWI1YmMxOTQxIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMTAtMDhUMDU6NDA6NDEuOTAyWiIgVmVyc2lvbj0iMi4wIj4KICAgIDxJc3N1ZXI+aHR0cDovL2FkZnMuZXhhbXBsZS9hZGZzL3NlcnZpY2VzL3RydXN0PC9Jc3N1ZXI+CiAgICA8ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4KICAgICAgPGRzOlNpZ25lZEluZm8+CiAgICAgICAgPGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgICAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+CiAgICAgICAgPGRzOlJlZmVyZW5jZSBVUkk9IiNfNDgzZjNiNGItNzJjMC00YWRjLTlhZTUtZDkyMWI1YmMxOTQxIj4KICAgICAgICAgIDxkczpUcmFuc2Zvcm1zPgogICAgICAgICAgICA8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz4KICAgICAgICAgICAgPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgogICAgICAgICAgPC9kczpUcmFuc2Zvcm1zPgogICAgICAgICAgPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+CiAgICAgICAgICA8ZHM6RGlnZXN0VmFsdWU+RElHRVNUPC9kczpEaWdlc3RWYWx1ZT4KICAgICAgICA8L2RzOlJlZmVyZW5jZT4KICAgICAgPC9kczpTaWduZWRJbmZvPgogICAgICA8ZHM6U2lnbmF0dXJlVmFsdWU+U0lHTkFUVVJFPC9kczpTaWduYXR1cmVWYWx1ZT4KICAgICAgPEtleUluZm8geG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgogICAgICAgIDxkczpYNTA5RGF0YT4KICAgICAgICAgIDxkczpYNTA5Q2VydGlmaWNhdGU+Q0VSVElGSUNBVEU8L2RzOlg1MDlDZXJ0aWZpY2F0ZT4KICAgICAgICA8L2RzOlg1MDlEYXRhPgogICAgICA8L0tleUluZm8+CiAgICA8L2RzOlNpZ25hdHVyZT4KICAgIDxTdWJqZWN0PgogICAgICA8TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6cGVyc2lzdGVudCI+cG90YXRvQGRvbWFpbjwvTmFtZUlEPgogICAgICA8U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPgogICAgICAgIDxTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTYtMTAtMDhUMDU6NDU6NDEuOTAyWiIgUmVjaXBpZW50PSJodHRwczovL3NpZ25pbi5hd3MuYW1hem9uLmNvbS9zYW1sIi8+CiAgICAgIDwvU3ViamVjdENvbmZpcm1hdGlvbj4KICAgIDwvU3ViamVjdD4KICAgIDxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0xMC0wOFQwNTo0MDo0MS44ODZaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMTAtMDhUMDY6NDA6NDEuODg2WiI+CiAgICAgIDxBdWRpZW5jZVJlc3RyaWN0aW9uPgogICAgICAgIDxBdWRpZW5jZT51cm46YW1hem9uOndlYnNlcnZpY2VzPC9BdWRpZW5jZT4KICAgICAgPC9BdWRpZW5jZVJlc3RyaWN0aW9uPgogICAgPC9Db25kaXRpb25zPgogICAgPEF0dHJpYnV0ZVN0YXRlbWVudD4KICAgICAgPEF0dHJpYnV0ZSBOYW1lPSJodHRwczovL2F3cy5hbWF6b24uY29tL1NBTUwvQXR0cmlidXRlcy9Sb2xlU2Vzc2lvbk5hbWUiPgogICAgICAgIDxBdHRyaWJ1dGVWYWx1ZT5Kb2huU3RhbW9zPC9BdHRyaWJ1dGVWYWx1ZT4KICAgICAgPC9BdHRyaWJ1dGU+CiAgICAgIDxBdHRyaWJ1dGUgTmFtZT0iaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS9TQU1ML0F0dHJpYnV0ZXMvUm9sZSI+CiAgICAgICAgPEF0dHJpYnV0ZVZhbHVlPmFybjphd3M6aWFtOjoxMjM0NTY3ODkxMjM6c2FtbC1wcm92aWRlci9BREZTLGFybjphd3M6aWFtOjoxMjM0NTY3ODkxMjM6cm9sZS9BZG1pbmlzdHJhdG9yQWNjZXNzPC9BdHRyaWJ1dGVWYWx1ZT4KICAgICAgICA8QXR0cmlidXRlVmFsdWU+YXJuOmF3czppYW06Ojk4NzY1NDMyMTMyMTpzYW1sLXByb3ZpZGVyL0FERlMsYXJuOmF3czppYW06Ojk4NzY1NDMyMTMyMTpyb2xlL0RldmVsb3BlckFjY2VzczwvQXR0cmlidXRlVmFsdWU+CiAgICAgIDwvQXR0cmlidXRlPgogICAgICA8QXR0cmlidXRlIE5hbWU9Imh0dHBzOi8vYXdzLmFtYXpvbi5jb20vU0FNTC9BdHRyaWJ1dGVzL1Nlc3Npb25EdXJhdGlvbiI+CiAgICAgICAgPEF0dHJpYnV0ZVZhbHVlPjM2MDA8L0F0dHJpYnV0ZVZhbHVlPgogICAgICA8L0F0dHJpYnV0ZT4KICAgIDwvQXR0cmlidXRlU3RhdGVtZW50PgogICAgPEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0xMC0wOFQwNTo0MDo0MS41NTlaIiBTZXNzaW9uSW5kZXg9Il80ODNmM2I0Yi03MmMwLTRhZGMtOWFlNS1kOTIxYjViYzE5NDEiPgogICAgICA8QXV0aG5Db250ZXh0PgogICAgICAgIDxBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvQXV0aG5Db250ZXh0Q2xhc3NSZWY+CiAgICAgIDwvQXV0aG5Db250ZXh0PgogICAgPC9BdXRoblN0YXRlbWVudD4KICA8L0Fzc2VydGlvbj4KPC9zYW1scDpSZXNwb25zZT4=",
			want: []types.Role{
				{
					Name:         "arn:aws:iam::123456789123:role/AdministratorAccess",
					PrincipalArn: "arn:aws:iam::123456789123:saml-provider/ADFS",
				},
				{
					Name:         "arn:aws:iam::987654321321:role/DeveloperAccess",
					PrincipalArn: "arn:aws:iam::987654321321:saml-provider/ADFS",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Logf("Running test -- %s", tt.name)
		types.Roles = []types.Role{}
		saml := Saml{
			Assertion: tt.input,
			Logger:    logrus.New(),
		}
		saml.DecodedSaml, _ = base64.StdEncoding.DecodeString(saml.Assertion)
		saml.parseSamlRoles()
		if !reflect.DeepEqual(types.Roles, tt.want) {
			t.Errorf("Error running test -- got: %v want: %v", types.Roles, tt.want)
		}
	}
}
