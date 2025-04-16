package envoy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindLatestVersion(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		expected string
	}{
		{
			name:     "empty list",
			versions: []string{},
			expected: "",
		},
		{
			name:     "single version",
			versions: []string{"1.0.0"},
			expected: "1.0.0",
		},
		{
			name:     "semver with v prefix",
			versions: []string{"v1.0.0", "v1.1.0", "v0.9.0"},
			expected: "v1.1.0",
		},
		{
			name:     "semver without v prefix",
			versions: []string{"1.0.0", "1.1.0", "0.9.0"},
			expected: "1.1.0",
		},
		{
			name:     "mixed semver with and without v prefix",
			versions: []string{"v1.0.0", "1.1.0", "v0.9.0"},
			expected: "1.1.0",
		},
		{
			name:     "real envoy versions",
			versions: []string{"v1.22.0", "v1.23.1", "v1.21.5", "v1.24.0"},
			expected: "v1.24.0",
		},
		{
			name:     "non-semver versions",
			versions: []string{"alpha", "beta", "rc1", "stable"},
			expected: "stable",
		},
		{
			name:     "mixed format versions",
			versions: []string{"1.0", "1.0.1", "1"},
			expected: "1.0.1",
		},
		{
			name:     "random version strings",
			versions: []string{"20220101", "20230101", "20210101"},
			expected: "20230101",
		},
		{
			name:     "complex mixed versions",
			versions: []string{"v1.2.3-alpha", "1.2.3", "v1.2.3-rc1", "v1.2.3"},
			expected: "v1.2.3-rc1", // Note: string comparison puts "-" after letters
		},
		{
			name:     "sha mixed versions",
			versions: []string{"v1.2.3@sha256:1234567890", "v1.2.2", "v1.2.3-rc1", "v1.2.3"},
			expected: "v1.2.3@sha256:1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findLatestVersion(tt.versions)
			assert.Equal(t, tt.expected, result)
		})
	}
}
