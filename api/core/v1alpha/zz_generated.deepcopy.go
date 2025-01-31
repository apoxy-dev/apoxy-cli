//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2025 Apoxy, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha

import (
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccessLog) DeepCopyInto(out *AccessLog) {
	*out = *in
	if in.FileAccessLog != nil {
		in, out := &in.FileAccessLog, &out.FileAccessLog
		*out = new(FileAccessLog)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessLog.
func (in *AccessLog) DeepCopy() *AccessLog {
	if in == nil {
		return nil
	}
	out := new(AccessLog)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Address) DeepCopyInto(out *Address) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Address.
func (in *Address) DeepCopy() *Address {
	if in == nil {
		return nil
	}
	out := new(Address)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Address) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddressList) DeepCopyInto(out *AddressList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Address, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddressList.
func (in *AddressList) DeepCopy() *AddressList {
	if in == nil {
		return nil
	}
	out := new(AddressList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AddressList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddressSpec) DeepCopyInto(out *AddressSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddressSpec.
func (in *AddressSpec) DeepCopy() *AddressSpec {
	if in == nil {
		return nil
	}
	out := new(AddressSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AddressStatus) DeepCopyInto(out *AddressStatus) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AddressStatus.
func (in *AddressStatus) DeepCopy() *AddressStatus {
	if in == nil {
		return nil
	}
	out := new(AddressStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Backend) DeepCopyInto(out *Backend) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Backend.
func (in *Backend) DeepCopy() *Backend {
	if in == nil {
		return nil
	}
	out := new(Backend)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Backend) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BackendEndpoint) DeepCopyInto(out *BackendEndpoint) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BackendEndpoint.
func (in *BackendEndpoint) DeepCopy() *BackendEndpoint {
	if in == nil {
		return nil
	}
	out := new(BackendEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BackendList) DeepCopyInto(out *BackendList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Backend, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BackendList.
func (in *BackendList) DeepCopy() *BackendList {
	if in == nil {
		return nil
	}
	out := new(BackendList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *BackendList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BackendSpec) DeepCopyInto(out *BackendSpec) {
	*out = *in
	if in.Endpoints != nil {
		in, out := &in.Endpoints, &out.Endpoints
		*out = make([]BackendEndpoint, len(*in))
		copy(*out, *in)
	}
	if in.DynamicProxy != nil {
		in, out := &in.DynamicProxy, &out.DynamicProxy
		*out = new(DynamicProxySpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BackendSpec.
func (in *BackendSpec) DeepCopy() *BackendSpec {
	if in == nil {
		return nil
	}
	out := new(BackendSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BackendStatus) DeepCopyInto(out *BackendStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BackendStatus.
func (in *BackendStatus) DeepCopy() *BackendStatus {
	if in == nil {
		return nil
	}
	out := new(BackendStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Domain) DeepCopyInto(out *Domain) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Domain.
func (in *Domain) DeepCopy() *Domain {
	if in == nil {
		return nil
	}
	out := new(Domain)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Domain) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainForwardingSpec) DeepCopyInto(out *DomainForwardingSpec) {
	*out = *in
	if in.ForwardingRules != nil {
		in, out := &in.ForwardingRules, &out.ForwardingRules
		*out = make([]ForwardingRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainForwardingSpec.
func (in *DomainForwardingSpec) DeepCopy() *DomainForwardingSpec {
	if in == nil {
		return nil
	}
	out := new(DomainForwardingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainList) DeepCopyInto(out *DomainList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Domain, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainList.
func (in *DomainList) DeepCopy() *DomainList {
	if in == nil {
		return nil
	}
	out := new(DomainList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DomainList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainSpec) DeepCopyInto(out *DomainSpec) {
	*out = *in
	if in.Subdomains != nil {
		in, out := &in.Subdomains, &out.Subdomains
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.CustomDomains != nil {
		in, out := &in.CustomDomains, &out.CustomDomains
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	in.Target.DeepCopyInto(&out.Target)
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(DomainTLSSpec)
		**out = **in
	}
	if in.ForwardingSpec != nil {
		in, out := &in.ForwardingSpec, &out.ForwardingSpec
		*out = new(DomainForwardingSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainSpec.
func (in *DomainSpec) DeepCopy() *DomainSpec {
	if in == nil {
		return nil
	}
	out := new(DomainSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainStatus) DeepCopyInto(out *DomainStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainStatus.
func (in *DomainStatus) DeepCopy() *DomainStatus {
	if in == nil {
		return nil
	}
	out := new(DomainStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainTLSSpec) DeepCopyInto(out *DomainTLSSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainTLSSpec.
func (in *DomainTLSSpec) DeepCopy() *DomainTLSSpec {
	if in == nil {
		return nil
	}
	out := new(DomainTLSSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainTargetDNS) DeepCopyInto(out *DomainTargetDNS) {
	*out = *in
	if in.IPs != nil {
		in, out := &in.IPs, &out.IPs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.FQDN != nil {
		in, out := &in.FQDN, &out.FQDN
		*out = new(string)
		**out = **in
	}
	if in.TXT != nil {
		in, out := &in.TXT, &out.TXT
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.MX != nil {
		in, out := &in.MX, &out.MX
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DKIM != nil {
		in, out := &in.DKIM, &out.DKIM
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.SPF != nil {
		in, out := &in.SPF, &out.SPF
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DMARC != nil {
		in, out := &in.DMARC, &out.DMARC
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.CAA != nil {
		in, out := &in.CAA, &out.CAA
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.SRV != nil {
		in, out := &in.SRV, &out.SRV
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.NS != nil {
		in, out := &in.NS, &out.NS
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DS != nil {
		in, out := &in.DS, &out.DS
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DNSKEY != nil {
		in, out := &in.DNSKEY, &out.DNSKEY
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainTargetDNS.
func (in *DomainTargetDNS) DeepCopy() *DomainTargetDNS {
	if in == nil {
		return nil
	}
	out := new(DomainTargetDNS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainTargetRef) DeepCopyInto(out *DomainTargetRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainTargetRef.
func (in *DomainTargetRef) DeepCopy() *DomainTargetRef {
	if in == nil {
		return nil
	}
	out := new(DomainTargetRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainTargetSpec) DeepCopyInto(out *DomainTargetSpec) {
	*out = *in
	if in.DNS != nil {
		in, out := &in.DNS, &out.DNS
		*out = new(DomainTargetDNS)
		(*in).DeepCopyInto(*out)
	}
	if in.Ref != nil {
		in, out := &in.Ref, &out.Ref
		*out = new(DomainTargetRef)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainTargetSpec.
func (in *DomainTargetSpec) DeepCopy() *DomainTargetSpec {
	if in == nil {
		return nil
	}
	out := new(DomainTargetSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainZone) DeepCopyInto(out *DomainZone) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainZone.
func (in *DomainZone) DeepCopy() *DomainZone {
	if in == nil {
		return nil
	}
	out := new(DomainZone)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DomainZone) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainZoneList) DeepCopyInto(out *DomainZoneList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Domain, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainZoneList.
func (in *DomainZoneList) DeepCopy() *DomainZoneList {
	if in == nil {
		return nil
	}
	out := new(DomainZoneList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DomainZoneList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainZoneSpec) DeepCopyInto(out *DomainZoneSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainZoneSpec.
func (in *DomainZoneSpec) DeepCopy() *DomainZoneSpec {
	if in == nil {
		return nil
	}
	out := new(DomainZoneSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DomainZoneStatus) DeepCopyInto(out *DomainZoneStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DomainZoneStatus.
func (in *DomainZoneStatus) DeepCopy() *DomainZoneStatus {
	if in == nil {
		return nil
	}
	out := new(DomainZoneStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DynamicProxyDnsCacheConfig) DeepCopyInto(out *DynamicProxyDnsCacheConfig) {
	*out = *in
	if in.DNSRefreshRate != nil {
		in, out := &in.DNSRefreshRate, &out.DNSRefreshRate
		*out = new(v1.Duration)
		**out = **in
	}
	if in.DNSMinRefreshRate != nil {
		in, out := &in.DNSMinRefreshRate, &out.DNSMinRefreshRate
		*out = new(v1.Duration)
		**out = **in
	}
	if in.HostTTL != nil {
		in, out := &in.HostTTL, &out.HostTTL
		*out = new(v1.Duration)
		**out = **in
	}
	if in.MaxHosts != nil {
		in, out := &in.MaxHosts, &out.MaxHosts
		*out = new(uint32)
		**out = **in
	}
	if in.DNSQueryTimeout != nil {
		in, out := &in.DNSQueryTimeout, &out.DNSQueryTimeout
		*out = new(v1.Duration)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DynamicProxyDnsCacheConfig.
func (in *DynamicProxyDnsCacheConfig) DeepCopy() *DynamicProxyDnsCacheConfig {
	if in == nil {
		return nil
	}
	out := new(DynamicProxyDnsCacheConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DynamicProxySpec) DeepCopyInto(out *DynamicProxySpec) {
	*out = *in
	if in.DnsCacheConfig != nil {
		in, out := &in.DnsCacheConfig, &out.DnsCacheConfig
		*out = new(DynamicProxyDnsCacheConfig)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DynamicProxySpec.
func (in *DynamicProxySpec) DeepCopy() *DynamicProxySpec {
	if in == nil {
		return nil
	}
	out := new(DynamicProxySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FileAccessLog) DeepCopyInto(out *FileAccessLog) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FileAccessLog.
func (in *FileAccessLog) DeepCopy() *FileAccessLog {
	if in == nil {
		return nil
	}
	out := new(FileAccessLog)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ForwardingRule) DeepCopyInto(out *ForwardingRule) {
	*out = *in
	if in.PortRanges != nil {
		in, out := &in.PortRanges, &out.PortRanges
		*out = make([]PortRange, len(*in))
		copy(*out, *in)
	}
	if in.TargetPort != nil {
		in, out := &in.TargetPort, &out.TargetPort
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ForwardingRule.
func (in *ForwardingRule) DeepCopy() *ForwardingRule {
	if in == nil {
		return nil
	}
	out := new(ForwardingRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ICEOffer) DeepCopyInto(out *ICEOffer) {
	*out = *in
	if in.Candidates != nil {
		in, out := &in.Candidates, &out.Candidates
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ICEOffer.
func (in *ICEOffer) DeepCopy() *ICEOffer {
	if in == nil {
		return nil
	}
	out := new(ICEOffer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PortRange) DeepCopyInto(out *PortRange) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PortRange.
func (in *PortRange) DeepCopy() *PortRange {
	if in == nil {
		return nil
	}
	out := new(PortRange)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Proxy) DeepCopyInto(out *Proxy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Proxy.
func (in *Proxy) DeepCopy() *Proxy {
	if in == nil {
		return nil
	}
	out := new(Proxy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Proxy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProxyList) DeepCopyInto(out *ProxyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Proxy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProxyList.
func (in *ProxyList) DeepCopy() *ProxyList {
	if in == nil {
		return nil
	}
	out := new(ProxyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ProxyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProxySpec) DeepCopyInto(out *ProxySpec) {
	*out = *in
	if in.AddressRef != nil {
		in, out := &in.AddressRef, &out.AddressRef
		*out = new(corev1.ObjectReference)
		**out = **in
	}
	if in.AccessLog != nil {
		in, out := &in.AccessLog, &out.AccessLog
		*out = new(AccessLog)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProxySpec.
func (in *ProxySpec) DeepCopy() *ProxySpec {
	if in == nil {
		return nil
	}
	out := new(ProxySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProxyStatus) DeepCopyInto(out *ProxyStatus) {
	*out = *in
	if in.StartTimestamp != nil {
		in, out := &in.StartTimestamp, &out.StartTimestamp
		*out = (*in).DeepCopy()
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProxyStatus.
func (in *ProxyStatus) DeepCopy() *ProxyStatus {
	if in == nil {
		return nil
	}
	out := new(ProxyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelNode) DeepCopyInto(out *TunnelNode) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelNode.
func (in *TunnelNode) DeepCopy() *TunnelNode {
	if in == nil {
		return nil
	}
	out := new(TunnelNode)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TunnelNode) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelNodeList) DeepCopyInto(out *TunnelNodeList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TunnelNode, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelNodeList.
func (in *TunnelNodeList) DeepCopy() *TunnelNodeList {
	if in == nil {
		return nil
	}
	out := new(TunnelNodeList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TunnelNodeList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelNodePeer) DeepCopyInto(out *TunnelNodePeer) {
	*out = *in
	if in.TunnelNodeRef != nil {
		in, out := &in.TunnelNodeRef, &out.TunnelNodeRef
		*out = new(TunnelNodeRef)
		**out = **in
	}
	if in.LabelSelector != nil {
		in, out := &in.LabelSelector, &out.LabelSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelNodePeer.
func (in *TunnelNodePeer) DeepCopy() *TunnelNodePeer {
	if in == nil {
		return nil
	}
	out := new(TunnelNodePeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelNodeRef) DeepCopyInto(out *TunnelNodeRef) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelNodeRef.
func (in *TunnelNodeRef) DeepCopy() *TunnelNodeRef {
	if in == nil {
		return nil
	}
	out := new(TunnelNodeRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelNodeSpec) DeepCopyInto(out *TunnelNodeSpec) {
	*out = *in
	if in.Peers != nil {
		in, out := &in.Peers, &out.Peers
		*out = make([]TunnelNodePeer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelNodeSpec.
func (in *TunnelNodeSpec) DeepCopy() *TunnelNodeSpec {
	if in == nil {
		return nil
	}
	out := new(TunnelNodeSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelNodeStatus) DeepCopyInto(out *TunnelNodeStatus) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelNodeStatus.
func (in *TunnelNodeStatus) DeepCopy() *TunnelNodeStatus {
	if in == nil {
		return nil
	}
	out := new(TunnelNodeStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelPeerOffer) DeepCopyInto(out *TunnelPeerOffer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelPeerOffer.
func (in *TunnelPeerOffer) DeepCopy() *TunnelPeerOffer {
	if in == nil {
		return nil
	}
	out := new(TunnelPeerOffer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TunnelPeerOffer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelPeerOfferList) DeepCopyInto(out *TunnelPeerOfferList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TunnelPeerOffer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelPeerOfferList.
func (in *TunnelPeerOfferList) DeepCopy() *TunnelPeerOfferList {
	if in == nil {
		return nil
	}
	out := new(TunnelPeerOfferList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TunnelPeerOfferList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelPeerOfferSpec) DeepCopyInto(out *TunnelPeerOfferSpec) {
	*out = *in
	if in.Offer != nil {
		in, out := &in.Offer, &out.Offer
		*out = new(ICEOffer)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelPeerOfferSpec.
func (in *TunnelPeerOfferSpec) DeepCopy() *TunnelPeerOfferSpec {
	if in == nil {
		return nil
	}
	out := new(TunnelPeerOfferSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TunnelPeerOfferStatus) DeepCopyInto(out *TunnelPeerOfferStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.PeerOffer != nil {
		in, out := &in.PeerOffer, &out.PeerOffer
		*out = new(ICEOffer)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TunnelPeerOfferStatus.
func (in *TunnelPeerOfferStatus) DeepCopy() *TunnelPeerOfferStatus {
	if in == nil {
		return nil
	}
	out := new(TunnelPeerOfferStatus)
	in.DeepCopyInto(out)
	return out
}
