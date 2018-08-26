package encryption

import (
	"encoding/json"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/renjuju/auth/dao"
	"github.com/renjuju/auth/models"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type EncryptionHandler struct {
	UserDao dao.UserDao
}

// GenerateSaltedPassword generates a salted password
func (e EncryptionHandler) GenerateSaltedPassword(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(500, err)
		return
	}

	logrus.Infof("body %v", string(body))
	var auth models.Auth
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

	c.JSON(200, models.AuthRepsonse{Hash: string(ePass)})
}

// Compares salted password & password
func (e EncryptionHandler) PasswordCompare(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(500, err)
		return
	}

	logrus.Infof("body %v", string(body))
	var auth models.Auth
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

// Login fakes a user login
func (e EncryptionHandler) Login(c *gin.Context) {
	data, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Errorf("unable to read request body %v", err)
		c.Status(401)
		return
	}

	var auth models.Auth
	err = json.Unmarshal(data, auth)
	if err != nil {
		logrus.Errorf("unable to unmarshal to auth struct: %v", err)
		c.Status(401)
		return
	}

	user, err := e.UserDao.GetUser(auth.Username, auth.Password)
	if err != nil {
		logrus.Errorf("unable to get user %v", err)
		return
	}

	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["data"] = user.Username

	tokenString, err := token.SignedString([]byte("my-signing-key"))
	if err != nil {
		logrus.Errorf("unable to sign token %v", err)
	}

	c.JSON(200, gin.H{
		"token": tokenString,
	})
}
