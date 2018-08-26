package dao

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	SaltedPassword string
	Username       string
}

type UserDao struct {
	UserData map[string]User
}

func (u UserDao) GetUser(userId, password string) (User, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.UserData[userId].SaltedPassword), []byte(password))
	if err != nil {
		return User{}, errors.New("incorrect password")
	}

	return u.UserData[userId], nil
}
