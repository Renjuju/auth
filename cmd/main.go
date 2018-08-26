package main

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/renjuju/auth/dao"
	"github.com/renjuju/auth/encryption"
	"github.com/renjuju/auth/models"
)

func main() {
	router := echo.New()
	router.Use(middleware.Logger())
	router.Use(middleware.Recover())

	userMap := make(map[string]models.User)
	userMap["testuser"] = models.User{
		SaltedPassword: "saltedPassword",
		Username:       "testuser",
	}

	userDao := dao.UserDao{
		UserData: userMap,
	}

	encryptionHandler := encryption.EncryptionHandler{UserDao: userDao}

	router.POST("/api/auth", encryptionHandler.GenerateSaltedPassword)
	router.POST("/api/decrypt", encryptionHandler.PasswordCompare)
	router.POST("/api/login", encryptionHandler.Login)

	router.Logger.Fatal(router.Start(":8080"))
}
