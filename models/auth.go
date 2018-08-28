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
	Username       string
	SaltedPassword string
}
