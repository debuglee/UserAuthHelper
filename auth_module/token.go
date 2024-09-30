package auth_module

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("my_secret_key") // 这应该存储在配置文件中

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// 生成JWT
func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour) // 设置JWT的过期时间为1小时
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	// 将 token 添加到白名单
	err = AddTokenToWhitelist(tokenString, expirationTime)
	if err != nil {
		return "", err
	}

	return tokenString, nil
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

	// 检查 token 是否在白名单中并且未过期
	if !IsTokenInWhitelist(tokenString) {
		return nil, jwt.NewValidationError("token is not whitelisted", jwt.ValidationErrorClaimsInvalid)
	}

	return claims, nil
}
