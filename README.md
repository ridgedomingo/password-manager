# Golang Password manager

Simple http go lang app that generates, and stores your user credentials (See postman collections for valid requests)

## Running the project locally

This project reads the aes key from env from cli.

1. cd `cmd/password-manager`
2. Then run `SECRET_KEY="_9zzSZGbJHcJmtek1D798p_my4eIscpKHWVrbdU5R1" AES_KEY=U23Fax5P17kBHNaawXz1780Gla3VIOp1 go run .`

## Running go docs

1. Run `godoc -http=:6060`
2. Open your browser and go to http://localhost:6060/pkg/github.com/ridgedomingo/password-manager/internal/routes/?m=all
