package auth

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// empty header
	headers := map[string][]string{}
	authHeader, err := GetAPIKey(headers)
	require.Error(t, err)
	assert.Equal(t, "no authorization header included", err.Error())
	assert.Equal(t, "", authHeader)

	// Valid header
	headers = map[string][]string{
		"Authorization": {"ApiKey my-secret-key"},
	}
	authHeader, err = GetAPIKey(headers)
	require.NoError(t, err)
	assert.Equal(t, "my-secret-key", authHeader)

	// Malformed header
	headers = map[string][]string{
		"Authorization": {"secretkey ApiKey"},
	}
	authHeader, err = GetAPIKey(headers)
	require.Error(t, err)
	assert.Equal(t, "malformed authorization header", err.Error())
	assert.Equal(t, "", authHeader)

	// Malformed header
	headers = map[string][]string{
		"Authorization": {"secretkey"},
	}
	authHeader, err = GetAPIKey(headers)
	require.Error(t, err)
	assert.Equal(t, "malformed authorization header", err.Error())
	assert.Equal(t, "", authHeader)

	// another way to test
	tests := map[string]struct {
		input              map[string][]string
		expectedAuthHeader string
		expectedErrorMsg   string
	}{
		"valid headers": {input: map[string][]string{
			"Authorization": {"ApiKey my-secret-key"},
		}, expectedAuthHeader: "my-secret-key", expectedErrorMsg: ""},
		"empty headers":                     {input: map[string][]string{}, expectedAuthHeader: "", expectedErrorMsg: "no authorization header included"},
		"malformed headers":                 {input: map[string][]string{"Authorization": {"secretkey ApiKey"}}, expectedAuthHeader: "", expectedErrorMsg: "malformed authorization header"},
		"malformed headers without space":   {input: map[string][]string{"Authorization": {"ApiKeysecretkey"}}, expectedAuthHeader: "", expectedErrorMsg: "malformed authorization header"},
		"malformed headers with only key":   {input: map[string][]string{"Authorization": {"ApiKey"}}, expectedAuthHeader: "", expectedErrorMsg: "malformed authorization header"},
		"malformed headers with only value": {input: map[string][]string{"Authorization": {"secretkey"}}, expectedAuthHeader: "", expectedErrorMsg: "malformed authorization header"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			authHeader, err := GetAPIKey(tc.input)
			if tc.expectedErrorMsg != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedErrorMsg, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedAuthHeader, authHeader)
			}
		})
	}
}
