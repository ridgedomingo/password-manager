package routes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
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

type UserCredentials struct {
	Username  string `json:"username"`
	Url       string `json:"url"`
	Password  string `json:"password"`
	Salt      string `json:"salt"`
	CreatedAt string `json:"created_at"`
}

func NewRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /generate-password", generatePassword)
	mux.HandleFunc("POST /credentials", saveCredentials)

	mux.HandleFunc("GET /credential/{username}", getUserCredentials)

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

func saveCredentials(w http.ResponseWriter, r *http.Request) {
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

func getUserCredentials(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")

	var rows *sql.Rows
	if username != "" {
		row, err := database.DBCon.Query("SELECT username, password_hash, url,salt, created_at FROM user_credentials WHERE username = $1", username)
		if err != nil {
			log.Fatal("ERROR QUERY", err)
		}
		rows = row
	}

	defer rows.Close()

	var userCredentials []UserCredentials
	for rows.Next() {
		var userCredential UserCredentials
		err := rows.Scan(&userCredential.Username, &userCredential.Password, &userCredential.Url, &userCredential.Salt, &userCredential.CreatedAt)
		if err != nil {
			http.Error(w, "Failed to scan row", http.StatusInternalServerError)
			log.Fatal("Failed to scan row:", err)
			return
		}
		userCredentials = append(userCredentials, userCredential)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Error during row iteration", http.StatusInternalServerError)
		log.Fatal("Error during row iteration:", err)
		return
	}

	// Create anonmyous struct to remove salt from response
	var response []interface{}
	for _, uc := range userCredentials {
		response = append(response, struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			Url       string `json:"url"`
			CreatedAt string `json:"created_at"`
		}{
			Username:  uc.Username,
			Password:  encrypt(uc.Password, uc.Salt), // Encrypt password with salt
			Url:       uc.Url,
			CreatedAt: uc.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func encrypt(plaintext, salt string) string {
	returnString := ""
	key, err := os.LookupEnv("AES_KEY")
	if !err {
		log.Fatal("Could not get env", err)
	} else {

		block, err := aes.NewCipher([]byte(key))
		if err != nil {
			log.Fatal("Error encrypting", err)
			returnString = ""
		}

		plaintextWithSalt := salt + plaintext

		ciphertext := make([]byte, aes.BlockSize+len(plaintextWithSalt))
		iv := ciphertext[:aes.BlockSize]
		if _, err := rand.Read(iv); err != nil {
			log.Fatal("Error reading encryption", err)
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintextWithSalt))

		returnString = base64.URLEncoding.EncodeToString(ciphertext)
	}
	return returnString
}
