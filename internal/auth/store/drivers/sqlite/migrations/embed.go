package migrations

import "embed"

//go:embed all:*.sql
var Migrations embed.FS
