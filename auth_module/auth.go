package auth_module

import (
	"encoding/json"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LogoutRequest struct {
	Token string `json:"token"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type Response struct {
	Code    int         `json:"code"`    // 状态码，例如 200 表示成功，400 表示请求错误等
	Message string      `json:"message"` // 状态的描述信息
	Data    interface{} `json:"data"`    // 返回的详细数据
}

func Login(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	var request LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest) // 设置 HTTP 状态码 400
		response := Response{Code: http.StatusBadRequest, Message: "Invalid request", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	var user User
	if err := db.Where("username = ?", request.Username).First(&user).Error; err != nil {
		w.WriteHeader(http.StatusUnauthorized) // 设置 HTTP 状态码 401
		response := Response{Code: http.StatusUnauthorized, Message: "User not found", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized) // 设置 HTTP 状态码 401
		response := Response{Code: http.StatusUnauthorized, Message: "Invalid password", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	token, err := GenerateJWT(user.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 设置 HTTP 状态码 500
		response := Response{Code: http.StatusInternalServerError, Message: "Error generating token", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	w.WriteHeader(http.StatusOK) // 设置 HTTP 状态码 200
	response := Response{
		Code:    http.StatusOK,
		Message: "Login successful",
		Data: map[string]interface{}{
			"token":    token,
			"username": user.Username,
			"email":    user.Email,
			"avatar":   user.Avatar,
		},
	}
	json.NewEncoder(w).Encode(response)
}

func Logout(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	var request LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest) // 设置 HTTP 状态码 400
		response := Response{Code: http.StatusBadRequest, Message: "Invalid request", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	err := RemoveTokenFromWhitelist(request.Token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 设置 HTTP 状态码 500
		response := Response{Code: http.StatusInternalServerError, Message: "Error removing token from whitelist", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	w.WriteHeader(http.StatusOK) // 设置 HTTP 状态码 200
	response := Response{Code: http.StatusOK, Message: "Logout successful", Data: nil}
	json.NewEncoder(w).Encode(response)
}

func Register(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	var request RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest) // 设置 HTTP 状态码 400
		response := Response{Code: http.StatusBadRequest, Message: "Invalid request", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	var existingUser User
	if err := db.Where("username = ? OR email = ?", request.Username, request.Email).First(&existingUser).Error; err == nil {
		w.WriteHeader(http.StatusConflict) // 设置 HTTP 状态码 409
		response := Response{Code: http.StatusConflict, Message: "User already exists", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 设置 HTTP 状态码 500
		response := Response{Code: http.StatusInternalServerError, Message: "Error encrypting password", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	newUser := User{
		Username: request.Username,
		Password: string(hashedPassword),
		Email:    request.Email,
		IsActive: true,
	}

	if err := db.Create(&newUser).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError) // 设置 HTTP 状态码 500
		response := Response{Code: http.StatusInternalServerError, Message: "Error creating user", Data: nil}
		json.NewEncoder(w).Encode(response)
		return
	}

	w.WriteHeader(http.StatusCreated) // 设置 HTTP 状态码 201
	response := Response{Code: http.StatusCreated, Message: "User registered successfully", Data: nil}
	json.NewEncoder(w).Encode(response)
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized) // 设置 HTTP 状态码 401
			response := Response{Code: http.StatusUnauthorized, Message: "Missing or invalid Authorization header", Data: nil}
			json.NewEncoder(w).Encode(response)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		_, err := ValidateJWT(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized) // 设置 HTTP 状态码 401
			response := Response{Code: http.StatusUnauthorized, Message: "Invalid or expired token", Data: nil}
			json.NewEncoder(w).Encode(response)
			return
		}

		next.ServeHTTP(w, r)
	})
}
