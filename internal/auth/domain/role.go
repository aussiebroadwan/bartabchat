package domain

import "time"

type Role struct {
	ID        string
	Name      string
	Scopes    []string // Parsed from space-delimited storage
	CreatedAt time.Time
	UpdatedAt time.Time
}
