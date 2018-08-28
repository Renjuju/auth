package models

// Auth datastructure
type Auth struct {
	User
	Password string `json:"password"`
}

// AuthResponse
type AuthRepsonse struct {
	Hash string
}

// User data
type User struct {
	Username       string
	SaltedPassword string
}
