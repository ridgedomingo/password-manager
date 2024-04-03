package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ridgedomingo/password-manager/internal/routes"
)

func main() {
	router := routes.NewRouter()

	port := 8081
	address := fmt.Sprintf(":%d", port)
	fmt.Printf("Server running on localhost %s \n", address)

	err := http.ListenAndServe(address, router)

	if err != nil {
		log.Fatal("Error while serving", err)
	}
}
