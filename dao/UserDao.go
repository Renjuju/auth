package dao

import (
	"errors"

	"github.com/renjuju/auth/models"
	"golang.org/x/crypto/bcrypt"
)

type UserDao struct {
	UserData map[string]models.User
}

func (u UserDao) GetUser(userId, password string) (models.User, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.UserData[userId].SaltedPassword), []byte(password))
	if err != nil {
		return models.User{}, errors.New("incorrect password")
	}

	return u.UserData[userId], nil
}
