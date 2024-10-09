package auth_module

import (
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// 从环境变量中读取 JWT 密钥
var jwtKey = []byte(os.Getenv("JWT_SECRET"))

// 从环境变量中读取 Refresh Token 密钥
var refreshSecretKey = []byte(os.Getenv("REFRESH_SECRET"))

type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// 生成JWT
func GenerateJWT(userID uint, username string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour) // 设置有效期为1小时
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()), // 添加签发时间
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// 验证JWT
func ValidateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

// 生成 Refresh Token
func GenerateRefreshToken(userID uint, username string) (string, error) {
	expirationTime := time.Now().Add(30 * 24 * time.Hour) // 设置 Refresh Token 有效期为30天
	claims := &RefreshClaims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()), // 添加签发时间
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshSecretKey)
}

// 验证 Refresh Token
func ValidateRefreshToken(tokenString string) (*RefreshClaims, error) {
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return refreshSecretKey, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

// 获取用户ID从JWT中
func GetUserIDFromToken(r *http.Request) (uint, error) {
	tokenString := r.Header.Get("Authorization")

	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	claims, err := ValidateJWT(tokenString)
	if err != nil {
		return 0, err
	}

	return claims.UserID, nil
}
