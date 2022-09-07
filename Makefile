install:
	go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest

docs: install
	gomarkdoc ./auth/ > ./auth/README.md
	gomarkdoc ./cmd/ > ./cmd/README.md
	gomarkdoc ./prompts/ > ./prompts/README.md
	gomarkdoc ./saml/ > ./saml/README.md
	gomarkdoc ./types/ > ./types/README.md
	gomarkdoc ./utils/ > ./utils/README.md