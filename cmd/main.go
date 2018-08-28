package main

import (
	"database/sql"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	_ "github.com/lib/pq"
	"github.com/renjuju/auth/dao"
	"github.com/renjuju/auth/encryption"
	"github.com/renjuju/auth/models"
	"github.com/sirupsen/logrus"
)

type User struct {
	Username string
	Password string
}

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

func exampleSql() {
	connStr := "user=postgres dbname=profile sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		logrus.Fatalf("unable to open sql connection %v", err)
	}

	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		logrus.Fatalf("unable to query db %v", err)
	}

	for rows.Next() {
		var user User
		err := rows.Scan(&user.Username, &user.Password)

		if err != nil {
			logrus.Fatalf("unable to query columns %v", err)
		}

		logrus.Infof("user data %v", user)
	}
}
