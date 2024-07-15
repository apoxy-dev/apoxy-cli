package apiserver

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// resourceObjWrapper is a wrapper around runtime.Object that implements the
// resource.Object interface.
type resourceObjWrapper struct {
	// Object is the runtime.Object that this wrapper wraps.
	runtime.Object
	// List is the list object corresponding to the object.
	List runtime.Object
	// GroupVersion is the group version of the object.
	GroupVersion metav1.GroupVersion
	// Resource is the resource name of the object. E.g., "pods".
	Resource string
}

func (r *resourceObjWrapper) GetObjectMeta() *metav1.ObjectMeta {
	// Extract *metav1.ObjectMeta from the object using reflection.
	return reflect.ValueOf(r.Object).Elem().FieldByName("ObjectMeta").Addr().Interface().(*metav1.ObjectMeta)
}

func (r *resourceObjWrapper) NamespaceScoped() bool {
	return false
}

func (r *resourceObjWrapper) New() runtime.Object {
	return r.Object
}

func (r *resourceObjWrapper) NewList() runtime.Object {
	return r.List
}

func (r *resourceObjWrapper) GetGroupVersionResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    r.GroupVersion.Group,
		Version:  r.GroupVersion.Version,
		Resource: r.Resource,
	}
}

func (r *resourceObjWrapper) IsStorageVersion() bool {
	return true
}
