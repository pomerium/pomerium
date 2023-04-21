// Package forms has helper functions for working with HTML forms.
package forms

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// A Form represents an HTML form.
type Form struct {
	Action string
	Method string
	Inputs map[string]string
}

// Parse parses all the forms in an HTML document.
func Parse(r io.Reader) []Form {
	root, err := html.Parse(r)
	if err != nil {
		return nil
	}

	var forms []Form
	var currentForm *Form
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			currentForm = &Form{Action: "", Method: http.MethodGet, Inputs: make(map[string]string)}
			for _, attr := range node.Attr {
				switch attr.Key {
				case "action":
					currentForm.Action = attr.Val
				case "method":
					currentForm.Method = strings.ToUpper(attr.Val)
				}
			}
		}

		if currentForm != nil && node.Type == html.ElementNode && node.Data == "input" {
			var name, value string
			for _, attr := range node.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "value":
					value = attr.Val
				}
			}
			if name != "" {
				currentForm.Inputs[name] = value
			}
		}

		for c := node.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
		if node.Type == html.ElementNode && node.Data == "form" {
			if currentForm != nil {
				forms = append(forms, *currentForm)
			}
			currentForm = nil
		}
	}
	visit(root)
	return forms
}

// NewRequestWithContext creates a new request from the form details.
func (f *Form) NewRequestWithContext(ctx context.Context, baseURL *url.URL) (*http.Request, error) {
	actionURL, err := url.Parse(f.Action)
	if err != nil {
		return nil, err
	}
	actionURL = baseURL.ResolveReference(actionURL)

	vs := make(url.Values)
	for k, v := range f.Inputs {
		vs.Set(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, f.Method, actionURL.String(), strings.NewReader(vs.Encode()))
	if err != nil {
		return nil, err
	}
	// TODO: handle multipart forms
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}
