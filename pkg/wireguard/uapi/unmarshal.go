package uapi

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"k8s.io/utils/set"
)

// Unmarshal parses the UAPI representation into the given value.
func Unmarshal(data string, v any) error {
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr {
		return fmt.Errorf("unmarshal target must be a pointer")
	}
	val = val.Elem()

	if !val.CanSet() {
		return fmt.Errorf("unmarshal target cannot be set")
	}

	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 2 {
			continue // skip malformed lines
		}
		key := parts[0]
		value := parts[1]

		if err := unmarshalField(val, key, value); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalField(structVal reflect.Value, key, value string) error {
	typ := structVal.Type()

	for i := 0; i < structVal.NumField(); i++ {
		field := structVal.Field(i)
		fieldType := typ.Field(i)

		tag := fieldType.Tag.Get("uapi")
		if tag == "" {
			continue
		}

		parts := strings.Split(tag, ",")
		tagName := parts[0]

		if tagName != key {
			continue
		}

		options := set.New(parts[1:]...)
		if err := setField(field, value, options); err != nil {
			return fmt.Errorf("error setting field %s: %w", key, err)
		}
		break
	}
	return nil
}

func setField(field reflect.Value, value string, options set.Set[string]) error {
	if field.Kind() == reflect.Ptr {
		// Handle pointer fields: allocate memory if nil
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
		return setField(field.Elem(), value, options)
	}

	switch field.Kind() {
	case reflect.String:
		if options.Has("hex") {
			keyData, err := hex.DecodeString(value)
			if err != nil {
				return err
			}

			value = base64.StdEncoding.EncodeToString(keyData)
		}

		field.SetString(value)
	case reflect.Bool:
		field.SetBool(value == "true")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intValue, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetInt(intValue)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uintValue, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetUint(uintValue)
	case reflect.Slice:
		return setSlice(field, value, options)
	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}

	return nil
}

func setSlice(slice reflect.Value, value string, options set.Set[string]) error {
	elemType := slice.Type().Elem()

	newElem := reflect.New(elemType).Elem()
	if elemType.Kind() == reflect.Ptr {
		newElem.Set(reflect.New(elemType.Elem()))
	}

	if err := setField(newElem, value, options); err != nil {
		return err
	}

	slice.Set(reflect.Append(slice, newElem))
	return nil
}
