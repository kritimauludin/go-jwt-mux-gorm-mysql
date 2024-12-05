package config

import "github.com/golang-jwt/jwt/v5"

var JWT_KEY = []byte("qwbvtywkannywowksnjet9012-1")

type JWTClaim struct {
	Username string
	jwt.RegisteredClaims
} 