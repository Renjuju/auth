package dao

import (
	"database/sql"
	"errors"

	"github.com/renjuju/auth/models"
	"golang.org/x/crypto/bcrypt"
)

type UserDao struct {
	Db *sql.DB
}

func (u UserDao) GetUser(userId, password string) (models.User, error) {
	rows, err := u.Db.Query("SELECT * FROM users where username = $1", userId)

	if err != nil {
		return models.User{}, err
	}

	var user models.User
	isNext := rows.Next()
	if !isNext {
		return models.User{}, errors.New("user not found")
	}

	err = rows.Scan(&user.Username, &user.SaltedPassword)
	if err != nil {
		return models.User{}, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.SaltedPassword), []byte(password))
	if err != nil {
		return models.User{}, errors.New("incorrect password")
	}

	return user, nil
}
