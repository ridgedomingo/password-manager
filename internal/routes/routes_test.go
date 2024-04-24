package routes_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ridgedomingo/password-manager/internal/database"
	"github.com/ridgedomingo/password-manager/internal/routes"

	"github.com/stretchr/testify/assert"
)

var username string

// UserCredentials represents the model for the users table
type UserCredentials struct {
	Username  string    `json:"username"`
	Url       string    `json:"url"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
}

func TestMain(m *testing.M) {
	// Initialize env var
	username = os.Getenv("username")
	if username == "" {
		log.Fatal("Forgot to add username flag")
	}

	// Run tests
	exitCode := m.Run()

	os.Exit(exitCode)
}

func generateRandomURL() string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	randomURL := make([]byte, 5)
	for i := range randomURL {
		randomURL[i] = charset[rand.Intn(len(charset))]
	}
	return fmt.Sprintf("%s%s%s", "test", string(randomURL), ".com")
}

func TestSaveUserCredentials(t *testing.T) {
	database.DBCon, _ = database.CreateConnection()
	database.DBCon.AutoMigrate(&routes.UserCredentials{})

	mux := routes.NewRouter()

	jwtTokenPayload := map[string]interface{}{
		"username": username,
	}

	jwtPayloadJson, _ := json.Marshal(jwtTokenPayload)

	jwtReq := httptest.NewRequest("POST", "/generate-token", bytes.NewBuffer(jwtPayloadJson))
	jwtRR := httptest.NewRecorder()
	mux.ServeHTTP(jwtRR, jwtReq)

	assert.Equal(t, http.StatusOK, jwtRR.Code)

	jwtToken := jwtRR.Body.String()

	userCredentialsPayload := map[string]interface{}{
		"username": username,
		"url":      generateRandomURL(),
	}
	userCredentialsJsonPayload, _ := json.Marshal(userCredentialsPayload)
	req := httptest.NewRequest("POST", "/credentials", bytes.NewBuffer(userCredentialsJsonPayload))
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var savedData UserCredentials
	if queryErr := database.DBCon.Where("username = ?", userCredentialsPayload["username"]).Where("url = ?", userCredentialsPayload["url"]).First(&savedData).Error; queryErr != nil {
		log.Print("query error", queryErr)
	}

	// Assert that the CreatedAt value is within an acceptable range of time
	// assert that it is not earlier than 1 second ago
	createdDateTime := time.Now().Add(-1 * time.Second)

	assert.Equal(t, userCredentialsPayload["username"], savedData.Username, "username does not match with the payload")
	assert.Equal(t, userCredentialsPayload["url"], savedData.Url, "url does not match with the payload")
	assert.True(t, savedData.CreatedAt.After(createdDateTime), "created date time does not match with the time")

}

func TestGetUserCredentials(t *testing.T) {
	database.DBCon, _ = database.CreateConnection()
	database.DBCon.AutoMigrate(&routes.UserCredentials{})
	mux := routes.NewRouter()

	jwtTokenPayload := map[string]interface{}{
		"username": username,
	}

	// Encode JSON data
	jwtPayloadJson, _ := json.Marshal(jwtTokenPayload)

	jwtReq := httptest.NewRequest("POST", "/generate-token", bytes.NewBuffer(jwtPayloadJson))
	jwtRR := httptest.NewRecorder()
	mux.ServeHTTP(jwtRR, jwtReq)

	assert.Equal(t, http.StatusOK, jwtRR.Code)

	jwtToken := jwtRR.Body.String()

	// Create a new HTTP request to test the GetUserCredentials handler
	req := httptest.NewRequest("GET", "/credential/"+username, nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Decode the response
	var response []map[string]interface{}
	err := json.NewDecoder(rr.Body).Decode(&response)
	if err != nil {
		t.Errorf("failed to decode response body: %v", err)
		return
	}
	assert.NoError(t, err)

	// Check if the expected properties exist in each object of the array
	expectedProperties := []string{"username", "url", "password", "created_at"}
	for _, obj := range response {
		for _, prop := range expectedProperties {
			assert.Contains(t, obj, prop, "expected property %q to be in response but it was not found %+v", prop, obj)
		}
	}
}
