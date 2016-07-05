package common

const (
	DefaultTierName = ".default"
	blank           = ""
)

// Return the tier name, or the default if blank.
func TierOrDefault(tier string) string {
	if tier == blank {
		return DefaultTierName
	} else {
		return tier
	}
}

// Return the tier name, or blank if the default.
func TierOrBlank(tier string) string {
	if tier == DefaultTierName {
		return blank
	} else {
		return tier
	}
}
