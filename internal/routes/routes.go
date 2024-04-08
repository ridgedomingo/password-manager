package routes

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/ridgedomingo/go-exercises/pkg/generator"
	"github.com/ridgedomingo/password-manager/internal/database"
)

type PasswordParams struct {
	Length              uint
	PasswordType        string
	IsNumbersIncluded   bool
	IsSymbolsIncluded   bool
	IsUppercaseIncluded bool
}

type PasswordGeneratorParams struct {
	Username string `json:"userName"`
	Url      string `json:"url"`
}

func NewRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /generate-password", generatePassword)
	mux.HandleFunc("POST /credentials", generateSecuredPassword)

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

func generateSecuredPassword(w http.ResponseWriter, r *http.Request) {
	body := json.NewDecoder(r.Body)
	params := new(PasswordGeneratorParams)
	err := body.Decode(&params)

	if err != nil {
		log.Fatal("Error while decoding", err)
	}

	// Check if Username is missing in request
	if params.Username == "" {
		http.Error(w, "Username is missing in the request body", http.StatusBadRequest)
		return
	}

	// Check if URL is missing in request
	if params.Url == "" {
		http.Error(w, "Url is missing in the request body", http.StatusBadRequest)
		return
	}

	passwordParams := generator.PasswordParams{
		Length:              20,
		PasswordType:        "random",
		IsNumbersIncluded:   true,
		IsUppercaseIncluded: true,
		IsSymbolsIncluded:   true,
	}

	salt, _ := generateSalt(16)

	password := generator.GeneratePassword(passwordParams)
	hashedPassword := hashPassword(password, salt)

	// Insert user credentials into the database
	_, err = database.DBCon.Exec("INSERT INTO user_credentials (username, password_hash, url,salt, created_at) VALUES ($1, $2, $3, $4, $5)",
		params.Username, hashedPassword, params.Url, salt, time.Now())
	if err != nil {
		http.Error(w, "Failed to insert user credentials into database", http.StatusInternalServerError)
		log.Fatal("Failed to insert user credentials into database:", err)
		return
	}

	w.Write([]byte("Credentials successfully saved"))
}

func hashPassword(password, salt string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password + salt))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func generateSalt(length int) (string, error) {
	// Calculate the number of bytes needed for the salt
	numBytes := length * 3 / 4 // Base64 encoding expands 3 bytes to 4 characters

	// Generate random bytes for the salt
	saltBytes := make([]byte, numBytes)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return "", err
	}

	salt := base64.RawURLEncoding.EncodeToString(saltBytes)

	// Truncate the salt to the desired length
	if len(salt) > length {
		salt = salt[:length]
	}

	return salt, nil
}
