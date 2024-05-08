package routes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

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

type GenerateJWTParams struct {
	Username string `json:"userName"`
}

type PasswordGeneratorParams struct {
	Username string `json:"userName"`
	Url      string `json:"url"`
}

type UserCredentials struct {
	Username  string    `json:"username"`
	Url       string    `json:"url"`
	Password  string    `json:"password"`
	Salt      string    `json:"salt"`
	CreatedAt time.Time `json:"created_at"`
}

type CustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type cacheEntry struct {
	Value      interface{}
	Expiration time.Time
}

var jwtUsername string
var (
	cache     = make(map[string]cacheEntry)
	cacheLock sync.RWMutex
)

func NewRouter() http.Handler {
	mux := http.NewServeMux()
	cacheCleanup()

	mux.HandleFunc("POST /generate-password", generatePassword)
	mux.HandleFunc("POST /credentials", authMiddleware(saveCredentials).ServeHTTP)
	mux.HandleFunc("POST /generate-token", generateToken)

	mux.HandleFunc("GET /credential/{username}", authMiddleware(getUserCredentials).ServeHTTP)

	mux.HandleFunc("DELETE /cache/{username}", authMiddleware(deleteCacheByUsername).ServeHTTP)
	mux.HandleFunc("DELETE /cache", authMiddleware(deleteCache).ServeHTTP)

	return mux
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := os.Getenv("SECRET_KEY")
		secretKey := []byte(key)
		if key == "" {
			log.Print("SECRET_KEY environment variable is not set")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

		// Validate the JWT token here
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Validate JWT token
		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Return the secret key for token validation
			return secretKey, nil
		})
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Validate token claims
		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*CustomClaims)
		if !ok || !token.Valid {
			fmt.Println("Invalid JWT token")
			return
		}
		jwtUsername = claims.Username

		// Call the next handler if the token is valid
		next.ServeHTTP(w, r)
	})
}

func cacheCleanup() {
	go func() {
		for {
			time.Sleep(10 * time.Minute)

			cacheLock.Lock()
			for key, entry := range cache {
				if time.Now().After(entry.Expiration) {
					delete(cache, key)
				}
			}
			cacheLock.Unlock()
		}
	}()
}

// Setter for cache
func setCache(key string, value interface{}) {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	cache[key] = cacheEntry{
		Value:      value,
		Expiration: time.Now().Add(3600 * time.Second), // 1 hour expiration,
	}
}

// Getter for cache
func getCache(key string) (interface{}, bool) {
	cacheLock.RLock()
	defer cacheLock.RUnlock()
	cachedData, ok := cache[key]
	if !ok || time.Now().After(cachedData.Expiration) {
		// Cache entry not found or expired
		return nil, false
	}
	return cachedData.Value, ok
}

func generateToken(w http.ResponseWriter, r *http.Request) {
	key := os.Getenv("SECRET_KEY")
	secretKey := []byte(key)

	if key == "" {
		log.Print("SECRET_KEY environment variable is not set")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	body := json.NewDecoder(r.Body)
	params := new(GenerateJWTParams)
	err := body.Decode(&params)

	if err != nil {
		log.Print(err)
	}
	claims := jwt.MapClaims{
		"username": params.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expiry time (1 day)
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		log.Print("Could not generate token", err)
	}
	w.Write([]byte(signedToken))
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

	if params.Username != jwtUsername {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err != nil {
		log.Print("Error while decoding json ", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
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
	userCredential := UserCredentials{
		Username: params.Username,
		Password: hashedPassword,
		Url:      params.Url,
		Salt:     salt,
	}
	database.DBCon.Create(&userCredential)
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

	if username != jwtUsername {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var userCredentials []UserCredentials
	if username != "" {
		err := database.DBCon.Where("username = ?", username).Find(&userCredentials).Error
		if err != nil {
			log.Fatal("ERROR QUERY", err)
		}
	}

	// Create anonmyous struct to remove salt from response
	var response []interface{}
	for _, uc := range userCredentials {
		encryptedPassword, err := encrypt(uc.Password, uc.Salt)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response = append(response, struct {
			Username  string    `json:"username"`
			Password  string    `json:"password"`
			Url       string    `json:"url"`
			CreatedAt time.Time `json:"created_at"`
		}{
			Username:  uc.Username,
			Password:  encryptedPassword, // Encrypt password with salt
			Url:       uc.Url,
			CreatedAt: uc.CreatedAt,
		})
	}

	if cachedResponse, ok := getCache(username + "_credentials"); ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cachedResponse)
		return
	}

	// Cache the response
	setCache(username+"_credentials", response)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func encrypt(plaintext, salt string) (string, error) {
	returnString := ""
	var returnError error
	key, err := os.LookupEnv("AES_KEY")
	if !err {
		log.Print("Could not get env")
		returnError = errors.New("something went wrong")
	} else {

		block, err := aes.NewCipher([]byte(key))
		if err != nil {
			log.Print("Error encrypting", err)
			returnError = errors.New("something went wrong")
		}

		plaintextWithSalt := salt + plaintext

		ciphertext := make([]byte, aes.BlockSize+len(plaintextWithSalt))
		iv := ciphertext[:aes.BlockSize]
		if _, err := rand.Read(iv); err != nil {
			returnError = err
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintextWithSalt))

		returnString = base64.URLEncoding.EncodeToString(ciphertext)
	}
	return returnString, returnError
}

func deleteCacheByUsername(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")

	if username != jwtUsername {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	cacheLock.Lock()
	delete(cache, username+"_credentials")
	defer cacheLock.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Cache deleted"))
}

func deleteCache(w http.ResponseWriter, r *http.Request) {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	cache = make(map[string]cacheEntry)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Cache deleted"))
}
