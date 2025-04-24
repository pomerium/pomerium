package oauth21

import "net/http"

func optionalFormParam(r *http.Request, key string) *string {
	if v := r.FormValue(key); v != "" {
		return &v
	}
	return nil
}
