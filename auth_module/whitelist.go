package auth_module

import (
	"time"
)

type WhitelistedToken struct {
	ID        uint      `gorm:"primaryKey"`
	Token     string    `gorm:"unique"`
	ExpiresAt time.Time // Token 的过期时间
	CreatedAt time.Time
}

// 检查 Token 是否在白名单中并且未过期
func IsTokenInWhitelist(token string) bool {
	var whitelistedToken WhitelistedToken
	result := DB.Where("token = ? AND expires_at > ?", token, time.Now()).First(&whitelistedToken)
	return result.Error == nil
}

// 将 Token 添加到白名单
func AddTokenToWhitelist(token string, expiresAt time.Time) error {
	whitelistedToken := WhitelistedToken{
		Token:     token,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	return DB.Create(&whitelistedToken).Error
}

// 删除白名单中的 Token (例如用户登出时)
func RemoveTokenFromWhitelist(token string) error {
	return DB.Where("token = ?", token).Delete(&WhitelistedToken{}).Error
}
