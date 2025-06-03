package config_test

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "github.com/apoxy-dev/apoxy/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy/config"
)

func TestConfigLoad(t *testing.T) {
	t.Run("Unversioned", func(t *testing.T) {
		config.ConfigFile = "testdata/config-unversioned.yaml"

		cfg, err := config.Load()
		require.NoError(t, err)

		assert.Equal(t, &configv1alpha1.Config{
			Verbose:        true,
			DashboardURL:   "https://dashboard.example.com",
			CurrentProject: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
			Projects: []configv1alpha1.Project{{
				ID:          uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				APIBaseURL:  "https://api.example.com",
				APIBaseHost: "api.example.com",
				APIKey:      "your_api_key_here",
			}},
		}, cfg)
	})

	t.Run("Versioned (v1alpha1)", func(t *testing.T) {
		config.ConfigFile = "testdata/config-v1alpha1.yaml"

		cfg, err := config.Load()
		require.NoError(t, err)

		assert.Equal(t, &configv1alpha1.Config{
			TypeMeta: metav1.TypeMeta{
				APIVersion: configv1alpha1.GroupVersion.String(),
				Kind:       "Config",
			},
			Verbose:        true,
			DashboardURL:   "https://dashboard.example.com",
			CurrentProject: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
			Projects: []configv1alpha1.Project{{
				ID:          uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				APIBaseURL:  "https://api.example.com",
				APIBaseHost: "api.example.com",
				APIKey:      "your_api_key_here",
			}},
		}, cfg)
	})
}

func TestConfigSave(t *testing.T) {
	config.ConfigFile = filepath.Join(t.TempDir(), "config.yaml")

	cfg := &configv1alpha1.Config{
		TypeMeta: metav1.TypeMeta{
			APIVersion: configv1alpha1.GroupVersion.String(),
			Kind:       "Config",
		},
		Verbose:        true,
		DashboardURL:   "https://dashboard.example.com",
		CurrentProject: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
		Projects: []configv1alpha1.Project{{
			ID:          uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
			APIBaseURL:  "https://api.example.com",
			APIBaseHost: "api.example.com",
			APIKey:      "your_api_key_here",
		}},
	}

	require.NoError(t, config.Store(cfg))

	readBackCfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, cfg, readBackCfg)
}
