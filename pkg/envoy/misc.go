package envoy

func firstNonEmpty[T interface{ ~string }](args ...T) T {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}
