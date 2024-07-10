// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package bootstrap

import (
	"fmt"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"

	"github.com/apoxy-dev/apoxy-cli/internal/gateway/utils/proto"
	_ "github.com/apoxy-dev/apoxy-cli/internal/gateway/xds/extensions" // DON'T REMOVE: import of all extensions
	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
)

// ApplyBootstrapConfig applies the bootstrap config to the default bootstrap config and return the result config.
func ApplyBootstrapConfig(boostrapConfig *egv1a1.ProxyBootstrap, defaultBootstrap string) (string, error) {
	bootstrapType := boostrapConfig.Type
	if bootstrapType != nil && *bootstrapType == egv1a1.BootstrapTypeMerge {
		mergedBootstrap, err := mergeBootstrap(defaultBootstrap, boostrapConfig.Value)
		if err != nil {
			return "", err
		}
		return mergedBootstrap, nil
	}
	return boostrapConfig.Value, nil
}

func mergeBootstrap(base, override string) (string, error) {
	dst := &bootstrapv3.Bootstrap{}
	if err := proto.FromYAML([]byte(base), dst); err != nil {
		return "", fmt.Errorf("failed to parse default bootstrap config: %w", err)
	}

	src := &bootstrapv3.Bootstrap{}
	if err := proto.FromYAML([]byte(override), src); err != nil {
		return "", fmt.Errorf("failed to parse override bootstrap config: %w", err)
	}

	proto.Merge(dst, src)

	if err := dst.Validate(); err != nil {
		return "", fmt.Errorf("failed to validate merged bootstrap config: %w", err)
	}

	data, err := proto.ToYAML(dst)
	if err != nil {
		return "", fmt.Errorf("failed to convert proto message to YAML: %w", err)
	}

	return string(data), nil
}
