package main

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/emersion/go-bcrypt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

// Get secret key from .env file
var SECRET_KEY = os.Getenv("SECRET_KEY")

// Structs for request validation
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type RegisterRequest struct {
	Name string `json:"name"`
	LoginRequest
}
type TodosRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}
type TodoItemResponse struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

func valJWT(token *jwt.Token) (any, error) {
	// Verify the signing method is HMAC
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, errors.New("Invalid singing method")
	}
	return []byte(SECRET_KEY), nil
}

func createJWT(id string) (string, error) {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{ID: id}).SignedString([]byte(SECRET_KEY))
	return token, err
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
		var body RegisterRequest
		err := ctx.ShouldBindJSON(&body)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())
			return
		}
		var exists bool
		err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", body.Email).Scan(&exists)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if exists {
			ctx.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
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
		token, err := createJWT(id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"token": token})
	})

	// Validate body, get hash and id, compare hash and pass, return token
	r.POST("/login", func(ctx *gin.Context) {
		var body LoginRequest
		err := ctx.ShouldBindJSON(&body)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())
			return
		}
		var hashedPassword, id string
		err = db.QueryRow("SELECT id, password FROM users WHERE email = ?", body.Email).Scan(&hashedPassword, &id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(body.Password))
		if err != bcrypt.ErrMismatchedHashAndPassword {
			ctx.JSON(http.StatusUnauthorized, err.Error())
			return
		}
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		token, err := createJWT(id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"token": token})
	})

	// Validate body, get parse and cast token, insert task into DB, return JSON
	r.POST("/todos", func(ctx *gin.Context) {
		var body TodosRequest
		err := ctx.ShouldBindJSON(&body)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())
			return
		}
		token := ctx.GetHeader("Authorization")
		if token == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}
		claims := jwt.RegisteredClaims{}
		_, err = jwt.ParseWithClaims(token, &claims, valJWT)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, err.Error())
			return
		}
		userID := claims.ID
		var taskID string
		err = db.QueryRow("INSERT INTO tasks (user_id, title, description) VALUES (?,?,?) RETURNING id", userID, body.Title, body.Description).Scan(&taskID)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		ctx.JSON(http.StatusOK, TodoItemResponse{
			ID:          taskID,
			Title:       body.Title,
			Description: body.Description,
		})
	})

	// Validate body, parse token, get user_id from tasks id and compare, update task, return JSON
	r.PUT("/todos/:id", func(ctx *gin.Context) {
		var body TodosRequest
		err := ctx.ShouldBindJSON(&body)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, err.Error())
			return
		}
		token := ctx.GetHeader("Authorization")
		if token == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}
		claims := jwt.RegisteredClaims{}
		_, err = jwt.ParseWithClaims(token, &claims, valJWT)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, err.Error())
			return
		}
		_, err = db.Exec("UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?", body.Title, body.Description, ctx.Param("id"), claims.ID)
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
			return
		}
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, TodoItemResponse{
			ID:          ctx.Param("id"),
			Title:       body.Title,
			Description: body.Description,
		})
	})

	// Validate token, get user_id from tasks id and compare
	r.DELETE("/todos/:id", func(ctx *gin.Context) {
		token := ctx.GetHeader("Authorization")
		if token == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}
		claims := jwt.RegisteredClaims{}
		_, err = jwt.ParseWithClaims(token, &claims, valJWT)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, err.Error())
			return
		}
		// TODO: Get the user id from the task, compare it to param
		var taskID string
		err := db.QueryRow("SELECT id FROM tasks WHERE user_id = ?", claims.ID).Scan(&taskID)
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
			return
		}
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		if taskID != ctx.Param("id") {
			ctx.JSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
			return
		}
		_, err = db.Exec("DELETE FROM tasks WHERE id = ?", ctx.Param("id"))
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		ctx.Status(http.StatusNoContent)
	})

	// Parse token, get and convert params, query total, and query tasks
	r.GET("/todos", func(ctx *gin.Context) {
		token := ctx.GetHeader("Authorization")
		if token == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
			return
		}
		claims := jwt.RegisteredClaims{}
		_, err := jwt.ParseWithClaims(token, &claims, valJWT)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		pageInt, err := strconv.Atoi(ctx.Query("page"))
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		limitInt, err := strconv.Atoi(ctx.Query("limit"))
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		var total int
		err = db.QueryRow("SELECT COUNT(*) FROM tasks WHERE user_id = ?", claims.ID).Scan(&total)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		offset := (pageInt - 1) * limitInt
		row, err := db.Query("SELECT id, title, description FROM tasks WHERE user_id = ? ORDER BY id LIMIT ?,?", claims.ID, offset, limitInt)
		var data []TodoItemResponse
		var id, title, description string
		for row.Next() {
			err := row.Scan(&id, &title, &description)
			if err != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			data = append(data, TodoItemResponse{
				ID:          id,
				Title:       title,
				Description: description,
			})
		}
		ctx.JSON(http.StatusOK, gin.H{
			"data":  data,
			"page":  pageInt,
			"limit": limitInt,
			"total": total,
		})
	})

	r.Run()
}
