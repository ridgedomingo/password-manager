package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // Import PostgreSQL driver
)

var (
	DBCon    *sql.DB
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "Postgre!!"
	dbname   = "postgres"
)

func CreateConnection() (*sql.DB, error) {
	connectionString := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	// PostgreSQL connection string
	// // Open the PostgreSQL database connection
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}
	// Ensure the database connection is still alive
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
