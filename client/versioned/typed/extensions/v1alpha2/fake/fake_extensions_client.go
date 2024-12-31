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
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha2 "github.com/apoxy-dev/apoxy-cli/client/versioned/typed/extensions/v1alpha2"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeExtensionsV1alpha2 struct {
	*testing.Fake
}

func (c *FakeExtensionsV1alpha2) EdgeFunctions() v1alpha2.EdgeFunctionInterface {
	return &FakeEdgeFunctions{c}
}

func (c *FakeExtensionsV1alpha2) EdgeFunctionRevisions() v1alpha2.EdgeFunctionRevisionInterface {
	return &FakeEdgeFunctionRevisions{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeExtensionsV1alpha2) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}