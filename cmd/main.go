package main

import (
	"github.com/gin-gonic/gin"
	"github.com/renjuju/auth/dao"
	"github.com/renjuju/auth/encryption"
	"github.com/renjuju/auth/models"
	"github.com/sirupsen/logrus"
)

func main() {
	router := gin.Default()

	userMap := make(map[string]models.User)
	userMap["testuser"] = models.User{
		SaltedPassword: "saltedPassword",
		Username:       "testuser",
	}

	userDao := dao.UserDao{
		UserData: userMap,
	}

	encryptionHandler := encryption.EncryptionHandler{UserDao: userDao}
	router.Handle("POST", "/api/auth", encryptionHandler.GenerateSaltedPassword)
	router.Handle("POST", "/api/decrypt", encryptionHandler.PasswordCompare)
	router.Handle("POST", "/api/login", encryptionHandler.Login)

	logrus.Fatal(router.Run("0.0.0.0:8080"))
}
