package tag

import (
	"reflect"
)

func Scopes(v interface{}) (scopes []string) {

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()

	}
	typ := val.Type()

	for i := 0; i < typ.NumField(); i++ {

		if scope, ok := typ.Field(i).Tag.Lookup("scope"); ok {
			if scope != "" {
				field := val.Field(i)
				if field.Kind() == reflect.Ptr {
					field = field.Elem()
				}
				if field.CanAddr() && field.Bool() {
					scopes = append(scopes, scope)
				}
			}
		}
	}

	return
}

func SetScopes(v interface{}, enable bool, scopes ...string) {

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()

	}
	typ := val.Type()

	in := func(scope string, scopes []string) bool {
		for _, s := range scopes {
			if s == scope {
				return true
			}
		}
		return false
	}

	for i := 0; i < typ.NumField(); i++ {

		if scope, ok := typ.Field(i).Tag.Lookup("scope"); ok {
			if in(scope, scopes) {
				field := val.Field(i)
				v := reflect.ValueOf(enable)
				if field.Kind() == reflect.Ptr {
					v = reflect.ValueOf(&enable)
				}
				if field.CanSet() {
					field.Set(v)
				}
			}
		}
	}
}
