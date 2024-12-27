//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2024 Apoxy, Inc.

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

package extensions

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunction) DeepCopyInto(out *EdgeFunction) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunction.
func (in *EdgeFunction) DeepCopy() *EdgeFunction {
	if in == nil {
		return nil
	}
	out := new(EdgeFunction)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *EdgeFunction) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionCodeSource) DeepCopyInto(out *EdgeFunctionCodeSource) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.JsSource != nil {
		in, out := &in.JsSource, &out.JsSource
		*out = new(JavaScriptSource)
		(*in).DeepCopyInto(*out)
	}
	if in.WasmSource != nil {
		in, out := &in.WasmSource, &out.WasmSource
		*out = new(WasmSource)
		**out = **in
	}
	if in.GoPluginSource != nil {
		in, out := &in.GoPluginSource, &out.GoPluginSource
		*out = new(GoPluginSource)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionCodeSource.
func (in *EdgeFunctionCodeSource) DeepCopy() *EdgeFunctionCodeSource {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionCodeSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionList) DeepCopyInto(out *EdgeFunctionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]EdgeFunction, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionList.
func (in *EdgeFunctionList) DeepCopy() *EdgeFunctionList {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *EdgeFunctionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionRevision) DeepCopyInto(out *EdgeFunctionRevision) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionRevision.
func (in *EdgeFunctionRevision) DeepCopy() *EdgeFunctionRevision {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionRevision)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *EdgeFunctionRevision) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionRevisionList) DeepCopyInto(out *EdgeFunctionRevisionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]EdgeFunctionRevision, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionRevisionList.
func (in *EdgeFunctionRevisionList) DeepCopy() *EdgeFunctionRevisionList {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionRevisionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *EdgeFunctionRevisionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionRevisionSpec) DeepCopyInto(out *EdgeFunctionRevisionSpec) {
	*out = *in
	in.Code.DeepCopyInto(&out.Code)
	if in.Env != nil {
		in, out := &in.Env, &out.Env
		*out = make([]EnvVar, len(*in))
		copy(*out, *in)
	}
	if in.Runtime != nil {
		in, out := &in.Runtime, &out.Runtime
		*out = new(EdgeFunctionRuntime)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionRevisionSpec.
func (in *EdgeFunctionRevisionSpec) DeepCopy() *EdgeFunctionRevisionSpec {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionRevisionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionRevisionStatus) DeepCopyInto(out *EdgeFunctionRevisionStatus) {
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

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionRevisionStatus.
func (in *EdgeFunctionRevisionStatus) DeepCopy() *EdgeFunctionRevisionStatus {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionRevisionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionRuntime) DeepCopyInto(out *EdgeFunctionRuntime) {
	*out = *in
	if in.Timeout != nil {
		in, out := &in.Timeout, &out.Timeout
		*out = new(v1.Duration)
		**out = **in
	}
	if in.Capabilities != nil {
		in, out := &in.Capabilities, &out.Capabilities
		*out = new(RuntimeCapabilities)
		(*in).DeepCopyInto(*out)
	}
	if in.Port != nil {
		in, out := &in.Port, &out.Port
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionRuntime.
func (in *EdgeFunctionRuntime) DeepCopy() *EdgeFunctionRuntime {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionRuntime)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionSpec) DeepCopyInto(out *EdgeFunctionSpec) {
	*out = *in
	in.Template.DeepCopyInto(&out.Template)
	if in.RevisionHistoryLimit != nil {
		in, out := &in.RevisionHistoryLimit, &out.RevisionHistoryLimit
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionSpec.
func (in *EdgeFunctionSpec) DeepCopy() *EdgeFunctionSpec {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EdgeFunctionStatus) DeepCopyInto(out *EdgeFunctionStatus) {
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

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EdgeFunctionStatus.
func (in *EdgeFunctionStatus) DeepCopy() *EdgeFunctionStatus {
	if in == nil {
		return nil
	}
	out := new(EdgeFunctionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EnvVar) DeepCopyInto(out *EnvVar) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EnvVar.
func (in *EnvVar) DeepCopy() *EnvVar {
	if in == nil {
		return nil
	}
	out := new(EnvVar)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GoPluginSource) DeepCopyInto(out *GoPluginSource) {
	*out = *in
	if in.URL != nil {
		in, out := &in.URL, &out.URL
		*out = new(string)
		**out = **in
	}
	if in.OCI != nil {
		in, out := &in.OCI, &out.OCI
		*out = new(OCIImageRef)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GoPluginSource.
func (in *GoPluginSource) DeepCopy() *GoPluginSource {
	if in == nil {
		return nil
	}
	out := new(GoPluginSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JavaScriptAssetsSource) DeepCopyInto(out *JavaScriptAssetsSource) {
	*out = *in
	if in.Files != nil {
		in, out := &in.Files, &out.Files
		*out = make([]SourceFile, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JavaScriptAssetsSource.
func (in *JavaScriptAssetsSource) DeepCopy() *JavaScriptAssetsSource {
	if in == nil {
		return nil
	}
	out := new(JavaScriptAssetsSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JavaScriptGitSource) DeepCopyInto(out *JavaScriptGitSource) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JavaScriptGitSource.
func (in *JavaScriptGitSource) DeepCopy() *JavaScriptGitSource {
	if in == nil {
		return nil
	}
	out := new(JavaScriptGitSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JavaScriptNpmSource) DeepCopyInto(out *JavaScriptNpmSource) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JavaScriptNpmSource.
func (in *JavaScriptNpmSource) DeepCopy() *JavaScriptNpmSource {
	if in == nil {
		return nil
	}
	out := new(JavaScriptNpmSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JavaScriptSource) DeepCopyInto(out *JavaScriptSource) {
	*out = *in
	if in.Assets != nil {
		in, out := &in.Assets, &out.Assets
		*out = new(JavaScriptAssetsSource)
		(*in).DeepCopyInto(*out)
	}
	if in.Git != nil {
		in, out := &in.Git, &out.Git
		*out = new(JavaScriptGitSource)
		**out = **in
	}
	if in.Npm != nil {
		in, out := &in.Npm, &out.Npm
		*out = new(JavaScriptNpmSource)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JavaScriptSource.
func (in *JavaScriptSource) DeepCopy() *JavaScriptSource {
	if in == nil {
		return nil
	}
	out := new(JavaScriptSource)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OCICredentials) DeepCopyInto(out *OCICredentials) {
	*out = *in
	if in.PasswordData != nil {
		in, out := &in.PasswordData, &out.PasswordData
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OCICredentials.
func (in *OCICredentials) DeepCopy() *OCICredentials {
	if in == nil {
		return nil
	}
	out := new(OCICredentials)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OCICredentialsObjectReference) DeepCopyInto(out *OCICredentialsObjectReference) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OCICredentialsObjectReference.
func (in *OCICredentialsObjectReference) DeepCopy() *OCICredentialsObjectReference {
	if in == nil {
		return nil
	}
	out := new(OCICredentialsObjectReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OCIImageRef) DeepCopyInto(out *OCIImageRef) {
	*out = *in
	if in.Credentials != nil {
		in, out := &in.Credentials, &out.Credentials
		*out = new(OCICredentials)
		(*in).DeepCopyInto(*out)
	}
	if in.CredentialsRef != nil {
		in, out := &in.CredentialsRef, &out.CredentialsRef
		*out = new(OCICredentialsObjectReference)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OCIImageRef.
func (in *OCIImageRef) DeepCopy() *OCIImageRef {
	if in == nil {
		return nil
	}
	out := new(OCIImageRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RuntimeCapabilities) DeepCopyInto(out *RuntimeCapabilities) {
	*out = *in
	if in.FetchAPI != nil {
		in, out := &in.FetchAPI, &out.FetchAPI
		*out = new(bool)
		**out = **in
	}
	if in.KV != nil {
		in, out := &in.KV, &out.KV
		*out = new(bool)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RuntimeCapabilities.
func (in *RuntimeCapabilities) DeepCopy() *RuntimeCapabilities {
	if in == nil {
		return nil
	}
	out := new(RuntimeCapabilities)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SourceFile) DeepCopyInto(out *SourceFile) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SourceFile.
func (in *SourceFile) DeepCopy() *SourceFile {
	if in == nil {
		return nil
	}
	out := new(SourceFile)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WasmSource) DeepCopyInto(out *WasmSource) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WasmSource.
func (in *WasmSource) DeepCopy() *WasmSource {
	if in == nil {
		return nil
	}
	out := new(WasmSource)
	in.DeepCopyInto(out)
	return out
}
