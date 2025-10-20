package domain

import "time"

type Invite struct {
	ID        string
	TokenHash string
	ClientID  string
	CreatedBy string
	RoleID    string // Role to assign to invited user
	ExpiresAt time.Time
	Reusable  bool
	Used      bool
	UsedBy    string // Can be empty string if not yet used
	CreatedAt time.Time
	UpdatedAt time.Time
}
