package models

// Auth datastructure
type Auth struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	SaltedPassword string `json:"saltedPassword"`
}

// AuthResponse
type AuthRepsonse struct {
	Hash string
}

// User data
type User struct {
	SaltedPassword string
	Username       string
}
