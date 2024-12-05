package middlewares

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/config"
	"github.com/kritimauludin/go-jwt-mux-gorm-mysql/helper"
)

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				helper.ResponseError(w, http.StatusInternalServerError, "Unauthorized / must be login")
				return
			}
		}

		//get token value
		tokenString := cookie.Value

		claims := &config.JWTClaim{}

		//parse token jwt
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			return config.JWT_KEY, nil
		})

		if err != nil {
			helper.ResponseError(w, http.StatusInternalServerError, "Token Invalid")
			return
		}

		if !token.Valid {
			helper.ResponseError(w, http.StatusInternalServerError, "Unauthorized / must be login")
			return
		}

		next.ServeHTTP(w, r)
	})
}