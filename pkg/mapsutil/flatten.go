package mapsutil

import (
	"fmt"
	"reflect"
)

// Flatten flattens a nested map into a single-level map, joining nested keys
// with a period. For example:
//
//	{ "a": { "b": { "c": 12345 } } } => { "a.b.c": [12345] }
func Flatten(m map[string]any) map[string][]any {
	flattened := make(map[string][]any)
	for k, v := range m {
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Map:
			subClaims := make(map[string]any)
			iter := rv.MapRange()
			for iter.Next() {
				subClaims[fmt.Sprint(iter.Key().Interface())] = iter.Value().Interface()
			}
			for sk, sv := range Flatten(subClaims) {
				flattened[k+"."+sk] = sv
			}
		case reflect.Slice:
			slc := make([]any, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				slc[i] = rv.Index(i).Interface()
			}
			flattened[k] = slc
		default:
			flattened[k] = []any{v}
		}
	}
	return flattened
}
