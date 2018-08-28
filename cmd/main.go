package main

import (
	"database/sql"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	_ "github.com/lib/pq"
	"github.com/renjuju/auth/dao"
	"github.com/renjuju/auth/encryption"
	"github.com/sirupsen/logrus"
)

type User struct {
	Username string
	Password string
}

func main() {
	connStr := "user=postgres dbname=profile sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		logrus.Fatalf("unable to open sql connection %v", err)
	}

	router := echo.New()
	router.Use(middleware.Logger())
	router.Use(middleware.Recover())

	userDao := dao.UserDao{
		Db: db,
	}

	encryptionHandler := encryption.EncryptionHandler{UserDao: userDao}

	router.POST("/api/auth", encryptionHandler.GenerateSaltedPassword)
	router.POST("/api/decrypt", encryptionHandler.PasswordCompare)
	router.POST("/api/login", encryptionHandler.Login)

	router.Logger.Fatal(router.Start(":8080"))
}
