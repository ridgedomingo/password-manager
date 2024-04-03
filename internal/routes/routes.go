package routes

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/ridgedomingo/go-exercises/pkg/generator"
)

type PasswordParams struct {
	Length              uint
	PasswordType        string
	IsNumbersIncluded   bool
	IsSymbolsIncluded   bool
	IsUppercaseIncluded bool
}

func NewRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /generate-password", generatePassword)

	return mux
}

func generatePassword(w http.ResponseWriter, r *http.Request) {
	body := json.NewDecoder(r.Body)
	params := new(PasswordParams)
	err := body.Decode(&params)

	if err != nil {
		log.Fatal("Error while decoding", err)
	}

	passwordParams := generator.PasswordParams{
		Length:              params.Length,
		PasswordType:        params.PasswordType,
		IsNumbersIncluded:   params.IsNumbersIncluded,
		IsUppercaseIncluded: params.IsUppercaseIncluded,
		IsSymbolsIncluded:   params.IsSymbolsIncluded,
	}
	password := generator.GeneratePassword(passwordParams)
	w.Write([]byte(password))
}
