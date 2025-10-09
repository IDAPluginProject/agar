package main

import (
	"database/sql"
	"errors"

	_ "github.com/ncruces/go-sqlite3/driver"

	_ "github.com/ncruces/go-sqlite3/embed"
)

var db *sql.DB

type user struct {
	Username   string `json:"username"`
	Bio        string `json:"bio"`
	StyleColor string `json:"style_color"`
}

type view struct {
	Username  string `json:"username"`
	Viewer    string `json:"viewer"`
	Timestamp string `json:"timestamp"`
}

func getDB() *sql.DB {
	if db != nil {
		return db
	}
	// Initialize sqlite database connection
	_db, err := sql.Open("sqlite3", "./secure_vault.db")
	if err != nil {
		panic(err)
	}
	// Create users table if it doesn't exist
	_, err = _db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username TEXT NOT NULL PRIMARY KEY,
		password TEXT NOT NULL,
		bio TEXT NOT NULL,
		style_color TEXT DEFAULT '#ffffff',
		otp INTEGER DEFAULT 0,
		auth_level INTEGER DEFAULT 0,
		secret TEXT,
		pow_a INTEGER DEFAULT 0
	);`)
	if err != nil {
		panic(err)
	}

	_, err = _db.Exec(`CREATE TABLE IF NOT EXISTS views (
		username TEXT NOT NULL REFERENCES users(username),
		viewer TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`)
	if err != nil {
		panic(err)
	}
	db = _db
	return db
}

func createUser(username, password, bio, secret string) error {
	_, err := getDB().Exec("INSERT INTO users (username, password, bio, secret) VALUES (?, ?, ?, ?)", username, password, bio, secret)
	return err
}

var errorNotFound = errors.New("user not found")

func loginUser(username, password string) (bool, error) {
	row := getDB().QueryRow("SELECT password FROM users WHERE username = ?", username)
	var expectedPassword string
	err := row.Scan(&expectedPassword)
	if err != nil {
		return false, nil // Password does not match
	}
	return expectedPassword == password, nil // Login successful
}

func addView(username, viewer string) error {
	_, err := getDB().Exec(`INSERT INTO views (username, viewer) VALUES (?, ?);`, username, viewer)
	return err
}

func getUserProfile(username string) (*user, error) {
	row := getDB().QueryRow("SELECT username, bio, style_color FROM users WHERE username = ?", username)
	var u user
	err := row.Scan(&u.Username, &u.Bio, &u.StyleColor)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errorNotFound // User not found
		}
		return nil, err // Other error
	}
	return &u, nil
}

func getUserViews(username string) ([]view, error) {
	rows, err := getDB().Query("SELECT username, viewer, timestamp FROM views WHERE username = ?", username)
	if err != nil {
		return nil, err // Error querying views
	}
	defer rows.Close()

	var views []view
	for rows.Next() {
		var v view
		if err := rows.Scan(&v.Username, &v.Viewer, &v.Timestamp); err != nil {
			return nil, err // Error scanning row
		}
		views = append(views, v)
	}

	if err := rows.Err(); err != nil {
		return nil, err // Error after iterating through rows
	}

	return views, nil
}

func updateStyleColor(username, color string) error {
	_, err := getDB().Exec("UPDATE users SET style_color = ? WHERE username = ?", color, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return errorNotFound // User not found
		}
		return err // Other error
	}
	return nil
}

func setOTP(username string, otp, auth_level int) error {
	_, err := getDB().Exec("UPDATE users SET otp = ?, auth_level = ? WHERE username = ?", otp, auth_level, username)
	return err
}

var errorInvalidOTP = errors.New("invalid OTP")

func getOTP(username string) (int, int, error) {
	row := getDB().QueryRow("SELECT otp, auth_level FROM users WHERE username = ?", username)
	var otp int
	var auth_level int
	err := row.Scan(&otp, &auth_level)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, errorNotFound // User not found
		}
		return 0, 0, err // Other error
	}
	if otp == 0 {
		return 0, 0, errorInvalidOTP
	}
	if otp < 0 || auth_level < 0 {
		return 0, 0, errors.New("OTP or auth level is negative")
	}
	return otp, auth_level, nil
}

func getSecret(username string) (string, error) {
	row := getDB().QueryRow("SELECT secret FROM users WHERE username = ?", username)
	var secret string
	err := row.Scan(&secret)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errorNotFound // User not found
		}
		return "", err // Other error
	}
	if secret == "" {
		return "", errors.New("secret not set for user")
	}
	return secret, nil
}
