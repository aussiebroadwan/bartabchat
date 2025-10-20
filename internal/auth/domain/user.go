package domain

import "time"

type User struct {
	ID            string
	Username      string
	PreferredName string
	PasswordHash  string     // argon2 encoded
	RoleID        string     // Foreign key to roles table
	MFAEnabled    *time.Time // Timestamp when MFA was enabled (nullable)
	MFASecret     *string    // TOTP secret (nullable, base32 encoded)
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
