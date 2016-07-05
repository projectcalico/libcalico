package backend

const (
	wildcard = "*"
)

// Return the ID, or a wildcard if the ID is blank.
func idOrWildcard(id string) string {
	if id != "" {
		return id
	} else {
		return wildcard
	}
}
