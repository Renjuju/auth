package encryption

import (
	"encoding/json"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type EncryptionHandler struct{}

func (e EncryptionHandler) Authenticate(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(500, err)
		return
	}

	logrus.Infof("body %v", string(body))
	var auth Auth
	err = json.Unmarshal(body, &auth)
	if err != nil {
		logrus.Errorf("unable to unmarshal json %v", err)
		c.JSON(500, err)
	}

	logrus.Infof("Auth data %v", auth)

	ePass, err := bcrypt.GenerateFromPassword([]byte(auth.Password), 1)

	if err != nil {
		logrus.Errorf("unable to generate password %v", err)
		c.JSON(500, err)
		return
	}

	c.JSON(200, AuthRepsonse{Hash: string(ePass)})
}

func (e EncryptionHandler) Decrypt(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(500, err)
		return
	}

	logrus.Infof("body %v", string(body))
	var auth Auth
	err = json.Unmarshal(body, &auth)
	if err != nil {
		logrus.Errorf("unable to unmarshal json %v", err)
		c.JSON(500, err)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(auth.SaltedPassword), []byte(auth.Password))
	if err != nil {
		c.JSON(403, err)
		return
	}

	c.JSON(200, gin.H{"message": "salted password matched unencrypted"})
}

func (e EncryptionHandler) Login(c *gin.Context) {
	user := Auth{
		Username: "Renju",
		Password: "testuser123",
	}

	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["admin"] = true
	claims["name"] = user.Username

	tokenString, err := token.SignedString([]byte("my-signing-key"))
	if err != nil {
		logrus.Errorf("unable to sign token %v", err)
	}

	c.JSON(200, gin.H{
		"token": tokenString,
	})
}

type Auth struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	SaltedPassword string `json:"saltedPassword"`
}

type AuthRepsonse struct {
	Hash string
}
