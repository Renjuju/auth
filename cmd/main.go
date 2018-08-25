package main

import (
	"github.com/gin-gonic/gin"
	"github.com/renjuju/hello/encryption"
	"github.com/sirupsen/logrus"
)

func main() {
	router := gin.Default()

	encryptionHandler := encryption.EncryptionHandler{}
	router.Handle("POST", "/api/auth", encryptionHandler.Authenticate)
	router.Handle("POST", "/api/decrypt", encryptionHandler.Decrypt)

	logrus.Fatal(router.Run("0.0.0.0:8080"))
}
