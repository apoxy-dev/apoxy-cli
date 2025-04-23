package net

import "fmt"

const (
	// ApoxyNetDomainSuffix is the domain suffix used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	ApoxyNetDomainSuffix = "apoxy.net"

	// EdgeFuncSubdomain is the subdomain used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	EdgeFuncSubdomain = "func"
	// TunnelSubdomain is the subdomain used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	TunnelSubdomain = "tun"
)

var (
	// EdgeFuncDomain is the domain used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	EdgeFuncDomain = fmt.Sprintf("%s.%s", EdgeFuncSubdomain, ApoxyNetDomainSuffix)

	// TunnelDomain is the domain used for the Apoxy endpoints serving
	// customer traffic (both internal and external).
	TunnelDomain = fmt.Sprintf("%s.%s", TunnelSubdomain, ApoxyNetDomainSuffix)
)
