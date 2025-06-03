package extensions

import (
	"fmt"
	"hash"
	"hash/fnv"

	"k8s.io/apimachinery/pkg/util/dump"
	"k8s.io/apimachinery/pkg/util/rand"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

// DeepHashObject hashes an object following the pointer values of
// the object.
// Copied from k8s.io/kubernetes/pkg/util/hash.
func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	fmt.Fprintf(hasher, "%v", dump.ForHash(objectToWrite))
}

// EdgeFunctionHash hashes an EdgeFunctionRevisionTemplate.
func EdgeFunctionHash(spec extensionsv1alpha2.EdgeFunctionRevisionSpec) string {
	h := fnv.New32a()
	DeepHashObject(h, spec)

	return rand.SafeEncodeString(fmt.Sprint(h.Sum32()))
}
