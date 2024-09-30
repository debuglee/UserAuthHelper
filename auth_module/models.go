package auth_module

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"unique"`
	Password string
	Email    string `gorm:"unique"`
	IsActive bool   `gorm:"default:true"`
	Avatar   string
}
