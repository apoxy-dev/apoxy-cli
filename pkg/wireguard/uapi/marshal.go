// Package uapi implements a marshaller for the WireGuard User-space API.
package uapi

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"strings"

	"k8s.io/utils/set"
)

// Marshal returns the UAPI representation of the given value.
func Marshal(v any) (string, error) {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	var sb strings.Builder
	if err := marshalStruct(val, &sb); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func marshalStruct(val reflect.Value, w io.Writer) error {
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		tag := fieldType.Tag.Get("uapi")
		if tag == "" {
			// Ignore fields without a UAPI tag.
			continue
		}

		// Split the tag by comma to separate the name and options
		parts := strings.Split(tag, ",")

		fieldName := parts[0]
		options := set.New(parts[1:]...)

		switch field.Kind() {
		case reflect.Ptr:
			if field.IsNil() {
				continue
			}
			fmt.Fprintf(w, "%s=%v\n", fieldName, marshalField(field.Elem(), fieldType, options))
		case reflect.Slice:
			for j := 0; j < field.Len(); j++ {
				fmt.Fprintf(w, "%s=%v\n", fieldName, marshalField(field.Index(j), fieldType, options))
			}
		default:
			fmt.Fprintf(w, "%s=%v\n", fieldName, marshalField(field, fieldType, options))
		}
	}
	return nil
}

func marshalField(field reflect.Value, fieldType reflect.StructField, options set.Set[string]) string {
	// In the WireGuard UAPI, keys are hex rather than base64 encoded.
	if options.Has("hex") {
		keyData, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%v", field.Interface()))
		if err != nil {
			return ""
		}
		return hex.EncodeToString(keyData)
	}

	switch field.Kind() {
	case reflect.Ptr:
		if field.IsNil() {
			return ""
		}
		return marshalField(field.Elem(), fieldType, options)
	case reflect.Bool:
		if field.Bool() {
			return "true"
		}
		return ""
	default:
		return fmt.Sprintf("%v", field.Interface())
	}
}
