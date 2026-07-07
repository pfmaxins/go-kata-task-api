package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/emersion/go-bcrypt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

// Hardcoded (wrong) signing key
const SUPER_SECRET_KEY = "jrq52348970b822hjkvcxcu972"

// Structs for request validation
type rLogin struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type rRegister struct {
	Name string `json:"name"`
	rLogin
}
type rTodos struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func main() {
	// Initialize database and tables
	db, err := sql.Open("sqlite3", "app.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	_, err = db.Exec(`
	PRAGMA foreign_keys = ON;
	CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name VARCHAR(254),
			email VARCHAR(254) UNIQUE,
			password BLOB
	);
	CREATE TABLE IF NOT EXISTS tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			title VARCHAR(254),
			description VARCHAR(254),
			CONSTRAINT fk_tasks_user
					FOREIGN KEY (user_id)
					REFERENCES users(id)
					ON DELETE CASCADE
	);
	`)
	if err != nil {
		log.Fatal(err.Error())
	}

	r := gin.Default()

	// Create register endpiont, check body, check email in use, encrypt password return token
	r.POST("/register", func(ctx *gin.Context) {
		var body rRegister
		err := ctx.ShouldBindJSON(&body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		exists := db.QueryRow("SELECT * FROM users WHERE email = ?", body.Email)
		if exists != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "email already in use"})
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		var id string
		err = db.QueryRow("INSERT INTO users (name, email, password) VALUES (?,?,?) RETURNING id", body.Name, body.Email, string(hashedPassword)).Scan(&id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{ID: id}).SignedString(SUPER_SECRET_KEY)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"token": token})
	})

	// Create a login endpoint, hash body password and return token
	r.POST("/login", func(ctx *gin.Context) {
		var body rLogin
		err := ctx.ShouldBindJSON(&body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		var hashedPassword string
		var id string
		err = db.QueryRow("SELECT id, password FROM users WHERE email = ?", body.Email).Scan(&hashedPassword, &id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(body.Password))
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{ID: id}).SignedString(SUPER_SECRET_KEY)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"token": token})
	})

	// Create a task, validate token, get claims, insert to table
	r.POST("/todos", func(ctx *gin.Context) {
		var body rTodos
		err := ctx.ShouldBindJSON(&body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		// TODO: learn how to parse token for claims (id), and query the DB
		// token := ctx.GetHeader("token")
		// claims := &jwt.RegisteredClaims{}
		// jwt.ParseWithClaims(token, claims)
	})
}
