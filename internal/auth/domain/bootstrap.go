package domain

type BootstrapData struct {
	AdminUsername      string
	AdminPreferredName string
	AdminPassword      string
	ClientName         string
	ClientScopes       []string
	Roles              []RoleDefinition
}

type RoleDefinition struct {
	Name   string
	Scopes []string
}
