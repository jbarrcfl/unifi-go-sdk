package unifi

// IntPtr returns a pointer to the given int value.
// Useful for setting optional config fields like MaxRetries.
func IntPtr(i int) *int { return &i }

// BoolPtr returns a pointer to the given bool value.
// Useful for setting optional model fields like Enabled.
func BoolPtr(b bool) *bool { return &b }

// StringPtr returns a pointer to the given string value.
// Useful for setting optional model fields.
func StringPtr(s string) *string { return &s }
