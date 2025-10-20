package authsdk

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	bootstrapRequiredReason = "required"
	bootstrapOnlyAlphanum   = "must only contain a-z, A-Z, 0-9, _ or -"
)

// Validate checks if the bootstrap request fields are valid.
// Returns a map of field names to error messages, or nil if all fields are valid.
func (b BootstrapRequest) Validate() map[string]string {
	errs := make(map[string]string)

	reName := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	reScope := regexp.MustCompile(`^[a-z][a-z0-9._-]*:[a-z][a-z0-9._-]*$`)

	b.validateUsername(errs, reName)
	b.validatePreferredName(errs)
	b.validatePassword(errs)
	b.validateClientName(errs, reName)
	b.validateClientScopes(errs, reScope)
	b.validateRoles(errs, reName, reScope)

	if len(errs) == 0 {
		return nil
	}
	return errs
}

func (b BootstrapRequest) validateUsername(errs map[string]string, reName *regexp.Regexp) {
	username := strings.TrimSpace(b.AdminUsername)
	switch {
	case username == "":
		errs["admin_username"] = bootstrapRequiredReason
	case len(username) < 3 || len(username) > 32:
		errs["admin_username"] = "must be 3-32 characters"
	case !reName.MatchString(username):
		errs["admin_username"] = bootstrapOnlyAlphanum
	}
}

func (b BootstrapRequest) validatePreferredName(errs map[string]string) {
	pref := strings.TrimSpace(b.AdminPreferredName)
	switch {
	case pref == "":
		errs["admin_preferred_name"] = bootstrapRequiredReason
	case len(pref) > 64:
		errs["admin_preferred_name"] = "too long (max 64)"
	}
}

func (b BootstrapRequest) validatePassword(errs map[string]string) {
	pw := b.AdminPassword
	switch {
	case pw == "":
		errs["admin_password"] = bootstrapRequiredReason
	case len(pw) < 8:
		errs["admin_password"] = "too short (min 8)"
	case len(pw) > 128:
		errs["admin_password"] = "too long (max 128)"
	}
}

func (b BootstrapRequest) validateClientName(errs map[string]string, reName *regexp.Regexp) {
	cname := strings.TrimSpace(b.ClientName)
	switch {
	case cname == "":
		errs["client_name"] = bootstrapRequiredReason
	case len(cname) > 100:
		errs["client_name"] = "too long (max 100)"
	case !reName.MatchString(cname):
		errs["client_name"] = bootstrapOnlyAlphanum
	}
}

func (b BootstrapRequest) validateClientScopes(errs map[string]string, reScope *regexp.Regexp) {
	if len(b.ClientScopes) == 0 {
		errs["client_scopes"] = "at least one scope required"
		return
	}

	seen := make(map[string]struct{}, len(b.ClientScopes))
	for _, s := range b.ClientScopes {
		if !reScope.MatchString(s) {
			errs["client_scopes"] = fmt.Sprintf("invalid scope: %q", s)
			return
		}
		if _, dup := seen[s]; dup {
			errs["client_scopes"] = "duplicate scopes"
			return
		}
		seen[s] = struct{}{}
	}
}

func (b BootstrapRequest) validateRoles(errs map[string]string, reName, reScope *regexp.Regexp) {
	if len(b.Roles) == 0 {
		errs["roles"] = "at least one role required"
		return
	}

	roleNames := make(map[string]struct{}, len(b.Roles))
	hasAdmin := false

	for i, role := range b.Roles {
		b.validateRole(errs, i, role, reName, reScope, roleNames, &hasAdmin)
	}

	if !hasAdmin {
		errs["roles"] = "must include 'admin' role"
	}
}

func (b BootstrapRequest) validateRole(
	errs map[string]string,
	index int,
	role RoleDefinition,
	reName, reScope *regexp.Regexp,
	roleNames map[string]struct{},
	hasAdmin *bool,
) {
	roleName := strings.TrimSpace(role.Name)

	switch {
	case roleName == "":
		errs[fmt.Sprintf("roles[%d].name", index)] = bootstrapRequiredReason
	case len(roleName) > 32:
		errs[fmt.Sprintf("roles[%d].name", index)] = "too long (max 32)"
	case !reName.MatchString(roleName):
		errs[fmt.Sprintf("roles[%d].name", index)] = bootstrapOnlyAlphanum
	default:
		if _, dup := roleNames[roleName]; dup {
			errs[fmt.Sprintf("roles[%d].name", index)] = "duplicate role name"
		} else {
			roleNames[roleName] = struct{}{}
			if roleName == "admin" {
				*hasAdmin = true
			}
		}
	}

	if len(role.Scopes) == 0 {
		errs[fmt.Sprintf("roles[%d].scopes", index)] = "at least one scope required"
	} else {
		for _, s := range role.Scopes {
			if !reScope.MatchString(s) {
				errs[fmt.Sprintf("roles[%d].scopes", index)] = fmt.Sprintf("invalid scope: %q", s)
				break
			}
		}
	}
}
