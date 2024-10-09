package auth_module

type User struct {
	ID          uint   `json:"id" gorm:"primaryKey"`
	Username    string `json:"username" gorm:"type:varchar(191);unique"` // 确保 username 为 VARCHAR(191)
	Password    string `json:"password"`
	Email       string `json:"email" gorm:"type:varchar(191);unique"` // 将 email 设为 VARCHAR(191)
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	DOB         string `json:"dob"`
	PhoneNumber string `json:"phone_number"`
	Address1    string `json:"address1"`
	Address2    string `json:"address2"`
	Country     string `json:"country"`
	State       string `json:"state"`
	Designation string `json:"designation"`
	Skills      string `json:"skills"`
	Note        string `json:"note"`
	IsActive    bool   `json:"is_active"`
	Avatar      string `json:"avatar"`
}
