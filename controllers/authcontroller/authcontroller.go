package authcontroller

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/config"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/helper"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var ResponseJson = helper.ResponseJson
var ResponseError = helper.ResponseError

func Login(w http.ResponseWriter, r *http.Request)  {
	var userInput models.User

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	
	defer r.Body.Close()

	//get data user by username
	var user models.User
	if err := models.DB.Where("username = ?", userInput.Username).First(&user).Error; err != nil {
		switch err {
		case gorm.ErrRecordNotFound :
			ResponseError(w, http.StatusUnauthorized, "Wrong username or password")
			return
		default :
			ResponseError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	
	//check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userInput.Password)); err != nil {
		ResponseError(w, http.StatusUnauthorized, "Wrong username or password")
		return
	}

	//generate token JWT
	expTime := time.Now().Add(time.Minute * 1)
	claims := &config.JWTClaim{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "go-jwt-mux-gorm-mysql",
			ExpiresAt: jwt.NewNumericDate(expTime),
		},
	}

	//declare algorithm jwt used
	tokenAlgo := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//signed token
	token, err := tokenAlgo.SignedString(config.JWT_KEY)
	if err != nil {
		ResponseError(w, http.StatusInternalServerError, err.Error())
		return
	}

	//set token to cokies
	http.SetCookie(w, &http.Cookie{
		Name: "token",
		Path: "/",
		Value: token,
		HttpOnly: true,
	})

	response := map[string]string{"message":"success login, token has been generate"}
	ResponseJson(w, http.StatusOK, response)
}
func Register(w http.ResponseWriter, r *http.Request)  {
	var userInput models.User

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userInput); err != nil {
		ResponseError(w, http.StatusBadRequest, err.Error())
		return
	}
	
	defer r.Body.Close()

	//hashing password with bcrypt
	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(userInput.Password), bcrypt.DefaultCost)
	userInput.Password = string(hashPassword)

	//insert data to database
	if err := models.DB.Create(&userInput).Error; err != nil {
		ResponseError(w, http.StatusInternalServerError, "Failed save data")
		return
	}

	response := map[string]string{"message":"success create account"}
	ResponseJson(w, http.StatusOK, response)
}
func Logout(w http.ResponseWriter, r *http.Request)  {
	//delete token from cokies
	http.SetCookie(w, &http.Cookie{
		Name: "token",
		Path: "/",
		Value: "",
		HttpOnly: true,
		MaxAge: -1,
	})

	response := map[string]string{"message":"success logout, token has been destroyed"}
	ResponseJson(w, http.StatusOK, response)
}