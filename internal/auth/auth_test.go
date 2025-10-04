package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed authorization header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer 12345"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "malformed authorization header - only one part",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345"},
			},
			expectedKey:   "12345",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if (err == nil) != (tt.expectedError == nil) {
				t.Fatalf("expected error %v, got %v", tt.expectedError, err)
			}

			if err != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("expected error %q, got %q", tt.expectedError, err)
			}
		})
	}
}
