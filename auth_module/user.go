package auth_module

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func UpdateUserProfile(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	userID, err := GetUserIDFromToken(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
			Data:    nil,
		})
		return
	}

	var updatedData User
	if err := json.NewDecoder(r.Body).Decode(&updatedData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Code:    http.StatusBadRequest,
			Message: "Invalid request data",
			Data:    nil,
		})
		return
	}

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{
			Code:    http.StatusNotFound,
			Message: "User not found",
			Data:    nil,
		})
		return
	}
	// 更新用户数据
	user.FirstName = updatedData.FirstName
	user.LastName = updatedData.LastName
	user.DOB = updatedData.DOB
	user.PhoneNumber = updatedData.PhoneNumber
	user.Address1 = updatedData.Address1
	user.Address2 = updatedData.Address2
	user.Country = updatedData.Country
	user.State = updatedData.State
	user.Designation = updatedData.Designation
	user.Skills = updatedData.Skills
	user.Note = updatedData.Note

	if err := db.Save(&user).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Code:    http.StatusInternalServerError,
			Message: "Error updating user profile",
			Data:    nil,
		})
		return
	}

	// 构造返回数据
	updatedProfile := map[string]interface{}{
		"first_name":   user.FirstName,
		"last_name":    user.LastName,
		"dob":          user.DOB,
		"phone_number": user.PhoneNumber,
		"address1":     user.Address1,
		"address2":     user.Address2,
		"country":      user.Country,
		"state":        user.State,
		"designation":  user.Designation,
		"skills":       user.Skills,
		"note":         user.Note,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Code:    http.StatusOK,
		Message: "Profile updated successfully",
		Data:    updatedProfile,
	})
}

// 修改后的 GetUserProfile
func GetUserProfile(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	userID, err := GetUserIDFromToken(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 构造返回的用户数据，并移除密码字段
	userResponse := map[string]interface{}{
		"id":           user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"first_name":   user.FirstName,
		"last_name":    user.LastName,
		"dob":          user.DOB,
		"phone_number": user.PhoneNumber,
		"address1":     user.Address1,
		"address2":     user.Address2,
		"country":      user.Country,
		"state":        user.State,
		"designation":  user.Designation,
		"skills":       user.Skills,
		"note":         user.Note,
		"is_active":    user.IsActive,
		"avatar":       user.Avatar,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Code:    http.StatusOK,
		Message: "User profile fetched successfully",
		Data:    userResponse,
	})
}

// 修改后的 ChangePassword
func ChangePassword(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	var request struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Code: http.StatusBadRequest, Message: "Invalid request", Data: nil})
		return
	}

	userID, err := GetUserIDFromToken(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Code: http.StatusUnauthorized, Message: "Invalid token", Data: nil})
		return
	}

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(Response{Code: http.StatusNotFound, Message: "User not found", Data: nil})
		return
	}

	// 检查旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.OldPassword)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Code: http.StatusUnauthorized, Message: "Old password is incorrect", Data: nil})
		return
	}

	// 更新新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Code: http.StatusInternalServerError, Message: "Error encrypting new password", Data: nil})
		return
	}

	user.Password = string(hashedPassword)

	if err := db.Save(&user).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Code: http.StatusInternalServerError, Message: "Error updating password", Data: nil})
		return
	}

	json.NewEncoder(w).Encode(Response{Code: http.StatusOK, Message: "Password updated successfully", Data: nil})
}
