package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedKey    string
		expectedError  error
		errorSubstring string
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key-123"},
			},
			expectedKey:   "test-api-key-123",
			expectedError: nil,
		},
		{
			name:           "Missing Authorization Header",
			headers:        http.Header{},
			expectedKey:    "",
			expectedError:  ErrNoAuthHeaderIncluded,
			errorSubstring: "no authorization header",
		},
		{
			name: "Malformed Authorization Header - Wrong Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer test-api-key-123"},
			},
			expectedKey:    "",
			errorSubstring: "malformed authorization header",
		},
		{
			name: "Malformed Authorization Header - Missing Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:    "",
			errorSubstring: "malformed authorization header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			// Check key value
			if key != tc.expectedKey {
				t.Errorf("expected key '%s', got '%s'", tc.expectedKey, key)
			}

			// Check error
			if tc.expectedError != nil {
				if err != tc.expectedError {
					t.Errorf("expected error '%v', got '%v'", tc.expectedError, err)
				}
			} else if tc.errorSubstring != "" {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tc.errorSubstring)
				} else if !strings.Contains(err.Error(), tc.errorSubstring) {
					t.Errorf("expected error containing '%s', got '%v'", tc.errorSubstring, err)
				}
			} else if err != nil {
				t.Errorf("expected no error, got '%v'", err)
			}
		})
	}
}
