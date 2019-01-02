package templates // import "github.com/pomerium/pomerium/internal/templates"

import (
	"html/template"
)

// New loads html and style resources directly. Panics on failure.
func New() *template.Template {
	t := template.New("authenticate-templates")
	template.Must(t.Parse(`
{{define "header.html"}}
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<style>
* {
    margin: 0;
    padding: 0;
}
body {
    font-family: "Helvetica Neue",Helvetica,Arial,sans-serif;
    font-size: 1em;
    line-height: 1.42857143;
    color: #333;
    background: #f0f0f0;
}
p {
    margin: 1.5em 0;
}
p:first-child {
    margin-top: 0;
}
p:last-child {
    margin-bottom: 0;
}
.container {
    max-width: 40em;
    display: block;
    margin: 10% auto;
    text-align: center;
}
.content, .message, button {
    border: 1px solid rgba(0,0,0,.125);
    border-bottom-width: 4px;
    border-radius: 4px;
}
.content, .message {
    background-color: #fff;
    padding: 2rem;
    margin: 1rem 0;
}
.error, .message {
    border-bottom-color: #c00;
}
.message {
    padding: 1.5rem 2rem 1.3rem;
}
header {
    border-bottom: 1px solid rgba(0,0,0,.075);
    margin: -2rem 0 2rem;
    padding: 2rem 0 1.8rem;
}
header h1 {
    font-size: 1.5em;
    font-weight: normal;
}
.error header {
    color: #c00;
}
.details {
    font-size: .85rem;
    color: #999;
}
button {
    color: #fff;
    background-color: #3B8686;
    cursor: pointer;
    font-size: 1.5rem;
    font-weight: bold;
    padding: 1rem 2.5rem;
    text-shadow: 0 3px 1px rgba(0,0,0,.2);
    outline: none;
}
button:active {
    border-top-width: 4px;
    border-bottom-width: 1px;
    text-shadow: none;
}
footer {
    font-size: 0.75em;
    color: #999;
    text-align: right;
    margin: 1rem;
}
</style>
{{end}}`))

	t = template.Must(t.Parse(`{{define "footer.html"}}Secured by <b>pomerium</b> {{end}}`))

	t = template.Must(t.Parse(`
{{define "sign_in_message.html"}}
  {{if eq (len .EmailDomains) 1}}
      {{if eq (index .EmailDomains 0) "@*"}}
          <p>You may sign in with any {{.ProviderName}} account.</p>
      {{else}}
          <p>You may sign in with your <b>{{index .EmailDomains 0}}</b> {{.ProviderName}} account.</p>
      {{end}}
  {{else if gt (len .EmailDomains) 1}}
      <p>
          You may sign in with any of these {{.ProviderName}} accounts:<br>
          {{range $i, $e := .EmailDomains}}{{if $i}}, {{end}}<b>{{$e}}</b>{{end}}
      </p>
  {{end}}
{{end}}`))

	t = template.Must(t.Parse(`
{{define "sign_in.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
	<title>Sign In</title>
	{{template "header.html"}}
</head>
<body>
    <div class="container">
        <div class="content">
            <header>
                <h1>Sign in to <b>{{.Destination}}</b></h1>
            </header>

            {{template "sign_in_message.html" .}}

            <form method="GET" action="/start">
                <input type="hidden" name="redirect_uri" value="{{.Redirect}}">
                <button type="submit" class="btn">Sign in with {{.ProviderName}}</button>
            </form>
        </div>

        <footer>{{template "footer.html"}} </br> {{.Version}} </footer>
    </div>
</body>
</html>
{{end}}`))

	template.Must(t.Parse(`
{{define "error.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
	<title>Error</title>
	{{template "header.html"}}
</head>
<body>
    <div class="container">
      <div class="content error">
        <header>
            <h1>{{.Title}}</h1>
        </header>
        <p>
          {{.Message}}<br>
          <span class="details">HTTP {{.Code}}</span>
        </p>
    </div>
        <footer>{{template "footer.html"}} </br> {{.Version}} </footer>
    </div>
</body>
</html>{{end}}`))

	t = template.Must(t.Parse(`
{{define "sign_out.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
	<title>Sign Out</title>
	{{template "header.html"}}
</head>
<body>
    <div class="container">
    	{{ if .Message }}
    	   <div class="message">{{.Message}}</div>
    	{{ end}}
    	<div class="content">
            <header>
                <h1>Sign out of <b>{{.Destination}}</b></h1>
            </header>

            <p>You're currently signed in as <b>{{.Email}}</b>. This will also sign you out of other internal apps.</p>
            <form method="POST" action="/sign_out">
              <input type="hidden" name="redirect_uri" value="{{.Redirect}}">
              <input type="hidden" name="sig" value="{{.Signature}}">
              <input type="hidden" name="ts" value="{{.Timestamp}}">
              <button type="submit">Sign out</button>
            </form>
    	</div>
    	<footer>{{template "footer.html"}} </br> {{.Version}}</footer>
    </div>
</body>
</html>
{{end}}`))
	return t
}
