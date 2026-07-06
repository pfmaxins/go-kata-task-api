package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Initialize database and tables
	db, err := sql.Open("sqlite3", "app.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT PRIMARY KEY AUTO_INCREMENT, 
			name VARCHAR(254),
			email VARCHAR(254) UNIQUE,
			password BLOB
		);

		CREATE TABLE IF NOT EXISTS tasks (
			id INT PRIMARY KEY AUTO_INCREMENT,
			user_id INT NOT NULL, 
			title VARCHAR(254),
			description VARCHAR(254),
			CONSTRAINT fk_tasks_user 
					FOREIGN KEY (user_id) 
					REFERENCES users(id) 
					ON DELETE CASCADE
		);
	`)
}
