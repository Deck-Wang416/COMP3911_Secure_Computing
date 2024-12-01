package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const dbPath = "../db.sqlite3"

func main() {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query("SELECT id, password FROM user")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var plainPassword string
		if err := rows.Scan(&id, &plainPassword); err != nil {
			log.Fatal(err)
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}

		_, err = db.Exec("UPDATE user SET password = ? WHERE id = ?", string(hashedPassword), id)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Updated password for user ID %d\n", id)
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}
