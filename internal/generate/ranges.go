package main

import "google.golang.org/protobuf/reflect/protoreflect"

type fieldNumberRanges [][2]protoreflect.FieldNumber

func (fnrs fieldNumberRanges) includes(fn protoreflect.FieldNumber) bool {
	for _, fnr := range fnrs {
		if fn >= fnr[0] && fn <= fnr[1] {
			return true
		}
	}
	return false
}
