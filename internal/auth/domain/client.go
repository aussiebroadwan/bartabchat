package domain

import "time"

type Client struct {
	ID         string
	Name       string
	SecretHash string
	Scopes     []string
	Protected  bool // If true, client cannot be deleted (e.g., bootstrap client)
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
