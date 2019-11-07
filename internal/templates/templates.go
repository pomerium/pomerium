package templates // import "github.com/pomerium/pomerium/internal/templates"

import (
	"html/template"
)

// New loads html and style resources directly. Panics on failure.
func New() *template.Template {
	t := template.New("pomerium-templates")
	template.Must(t.Parse(`
{{define "header.html"}}
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<style>
* {
    margin: 0;
    padding: 0;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    -webkit-text-size-adjust: none;
    box-sizing: border-box;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,'Helvetica Neue', sans-serif;
    font-size: 15px;
    line-height: 1.4em;
  }
  
  body {
    display: flex;
    flex-direction: row;
    align-items: center;
    background: #F8F8FF;
  }

  #main {
    width: 100%;
    height: 100vh;
    text-align: center;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  

  #info-box {
    max-width: 480px;
    width: 480px;
    margin-top: 200px;
    margin-right: auto;
    margin-bottom: 0px;
    margin-left: auto;    
    justify-content: center;
    flex-grow: 1;
  }
  
  section {
    display: flex;
    flex-direction: column;
    position: relative;
    text-align: left;
  }
  
  h1 {
    font-size: 36px;
    font-weight: 400;
    text-align: center;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    color: #32325d;
  }
  
  h1.title {
    text-align: center;
    background: #F8F8FF;
    margin: 15px 0;
  }

  h2 {
    margin: 15px 0;
    color: #32325d;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    font-size: 18px;
    font-weight: 650;
    padding-top: 20px;
  }
  
  .card {
    margin: 0 -30px;
    padding: 20px 30px 30px;
    border-radius: 4px;
    border: 1px solid #e8e8fb;
    background-color: #F8F8FF;
  }
    
  fieldset {
    margin-bottom: 20px;
    background: #FCFCFF;
    box-shadow: 0 1px 3px 0 rgba(50, 50, 93, 0.15), 0 4px 6px 0 rgba(112, 157, 199, 0.15);
    border-radius: 4px;
    border: none;
    font-size: 0;
  }
  
  fieldset label {
    position: relative;
    display: flex;
    flex-direction: row;
    height: 42px;
    padding: 10px 0;
    align-items: center;
    justify-content: center;
    font-weight: 400;
  }
  
  fieldset label:not(:last-child) {
    border-bottom: 1px solid #f0f5fa;
  }
    
  fieldset label span {
    min-width: 125px;
    padding: 0 15px;
    text-align: right;
  }
  
  #group {
    display: flex;
    align-items: center;
  }
  

  #group::before {
    display: inline-flex;
    content: '';
    height: 15px;
    background-position: -1000px -1000px;
    background-repeat: no-repeat;
    // margin-right: 10px;
  }
  
  .icon {
    display: inline-table;
    margin-top: -72px;
    background: #F8F8FF;
    text-align: center;
    width: 75px;
    height: auto;  
    border-radius: 50%;
  }
  
  .logo {
    padding-bottom: 20px;
    padding-top: 20px;
    width: 115px;
    height: auto;  
  }

  .ok{
    fill: #6E43E8;
  }

  .error{
    fill: #EB292F;
  }

  p.message {
    margin-top: 10px;
    margin-bottom: 10px;
    padding-bottom: 20px;
  }

  .field {
    flex: 1;
    padding: 0 15px;
    background: transparent;
    font-weight: 400;
    color: #31325f;
    outline: none;
    cursor: text;
  }
  
  fieldset .select::after {
    content: '';
    position: absolute;
    width: 9px;
    height: 5px;
    right: 20px;
    top: 50%;
    margin-top: -2px;
    pointer-events: none;
    background: #6E43E8 url("data:image/svg+xml;utf8,<svg viewBox='0 0 140 140' width='24' height='24' xmlns='http://www.w3.org/2000/svg'><g><path d='m121.3,34.6c-1.6-1.6-4.2-1.6-5.8,0l-51,51.1-51.1-51.1c-1.6-1.6-4.2-1.6-5.8,0-1.6,1.6-1.6,4.2 0,5.8l53.9,53.9c0.8,0.8 1.8,1.2 2.9,1.2 1,0 2.1-0.4 2.9-1.2l53.9-53.9c1.7-1.6 1.7-4.2 0.1-5.8z' fill='white'/></g></svg>") no-repeat;

  }
  
  input {
    flex: 1;
    border-style: none;
    outline: none;
    color: #313b3f;
  }
  
  select {
    flex: 1;
    border-style: none;
    outline: none;
    -webkit-appearance: none;
    -moz-appearance: none;
    appearance: none;
    outline: none;
    color: #313b3f;
    cursor: pointer;
    background: transparent;
  }

.flex{
  display: flex;
  flex-direction: row;
  flex-wrap: wrap;
  justify-content: space-between;

}

.button {
    color: #FCFCFF;
    background: #6E43E8;
    box-shadow: 0 4px 6px rgba(50, 50, 93, 0.11), 0 1px 3px rgba(0, 0, 0, 0.08);
    border-radius: 4px;
    border: 0;
    font-weight: 700;
    width: 50%;
    height: 40px;
    outline: none;
    cursor: pointer;
    padding: 10px;
    text-decoration: none;
  }

.button.half{
    flex-grow:0;
    flex-shrink:0;
    flex-basis:calc(50% - 10px);
}

.button.full{
  flex-grow:1;
}

.button:hover {
  transform: translateY(-1px);
  box-shadow: 0 7px 14px 0 rgba(50, 50, 93, 0.1), 0 3px 6px 0 rgba(0, 0, 0, 0.08);
}
.off-color{
  background: #5735B5;
}
  
</style>
{{end}}`))

	template.Must(t.Parse(`
{{define "error.html"}}
<!DOCTYPE html>
<html lang="en" charset="utf-8">
<head>
	<title>{{.Code}} - {{.Title}}</title>
	{{template "header.html"}}
</head>
<body>
  <div id="main">
    <div id="info-box">    
      <div class="card">
      <svg class="icon error" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="none" d="M0 0h24v24H0V0z"/><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9C4.63 15.55 4 13.85 4 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1C19.37 8.45 20 10.15 20 12c0 4.42-3.58 8-8 8z"/></svg>
        <h1 class="title">{{.Title}}</h1>
        <section>
          <p class="message">
            {{if .Message}}{{.Message}}</br>{{end}}
            {{if .CanDebug}}Troubleshoot your <a href="/.pomerium/">session</a>.</br>{{end}}
            {{if .RequestID}} Request {{.RequestID}}</br>{{end}}
          
          </p>
        </section>
      </form>
      </div>
      </div>
      <footer>
          <a href="https://www.pomerium.io" style="display: block;">
            <svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 139 30"><defs><style>.a {fill: #6e43e8;}.a,.b {fill-rule: evenodd;}.b,.c {fill: #fff;}</style></defs><title>powered-by-pomerium</title><path class="a" d="M10.6,5.5H138.4c3.09,0,5.6,2,5.6,4.39V31.11c0,2.42-2.51,4.39-5.6,4.39H10.6c-3.09,0-5.6-2-5.6-4.39V9.89C5,7.47,7.51,5.5,10.6,5.5Z" transform="translate(-5 -5.5)" /><path class="b" d="M75.4,26.62H73.94l1.13-2.79-2.25-5.69h1.54L75.78,22l1.43-3.87h1.54Zm-5.61-2.44a2.42,2.42,0,0,1-1.5-.55V24H66.78V15.56h1.51v3a2.48,2.48,0,0,1,1.5-.55c1.58,0,2.66,1.28,2.66,3.09S71.37,24.18,69.79,24.18Zm-.32-4.88a1.68,1.68,0,0,0-1.18.53v2.52a1.65,1.65,0,0,0,1.18.54c.85,0,1.44-.73,1.44-1.8S70.32,19.3,69.47,19.3Zm-8.8,4.33a2.38,2.38,0,0,1-1.5.55c-1.57,0-2.66-1.27-2.66-3.09S57.6,18,59.17,18a2.44,2.44,0,0,1,1.5.55v-3h1.52V24H60.67Zm0-3.8a1.63,1.63,0,0,0-1.17-.53c-.86,0-1.45.73-1.45,1.79s.59,1.8,1.45,1.8a1.6,1.6,0,0,0,1.17-.54Zm-9,1.68A1.69,1.69,0,0,0,53.47,23a3.55,3.55,0,0,0,1.76-.56v1.26a4.73,4.73,0,0,1-2,.46,3,3,0,0,1-3-3.13A2.87,2.87,0,0,1,53.11,18,2.66,2.66,0,0,1,55.7,21a5.53,5.53,0,0,1,0,.56Zm1.37-2.34a1.38,1.38,0,0,0-1.37,1.36h2.57A1.28,1.28,0,0,0,53.05,19.17Zm-5.34.93V24H46.2v-5.9h1.51v.59A2,2,0,0,1,49.16,18a1.65,1.65,0,0,1,.49.06v1.35a1.83,1.83,0,0,0-.53-.07A1.87,1.87,0,0,0,47.71,20.1ZM41,21.51A1.69,1.69,0,0,0,42.76,23a3.55,3.55,0,0,0,1.76-.56v1.26a4.73,4.73,0,0,1-2,.46,3,3,0,0,1-3-3.13A2.87,2.87,0,0,1,42.4,18,2.66,2.66,0,0,1,45,21a5.53,5.53,0,0,1,0,.56Zm1.37-2.34A1.38,1.38,0,0,0,41,20.53h2.57A1.28,1.28,0,0,0,42.34,19.17ZM35.7,24l-1.2-4-1.2,4H32l-2-5.9h1.51l1.19,4,1.19-4h1.37l1.19,4,1.19-4h1.51l-2,5.9Zm-9.23.14a2.94,2.94,0,0,1-3-3.09,3,3,0,1,1,6.07,0A2.94,2.94,0,0,1,26.47,24.18Zm0-4.92c-.88,0-1.49.75-1.49,1.83s.61,1.83,1.49,1.83S28,22.18,28,21.09,27.35,19.26,26.47,19.26Zm-6.62,1.87H18.49V24H17V15.93h2.87a2.61,2.61,0,1,1,0,5.2Zm-.22-4H18.49V19.9h1.14a1.38,1.38,0,1,0,0-2.75Z" transform="translate(-5 -5.5)" /><path class="c" d="M132.71,14.9A3.93,3.93,0,0,0,128.78,11H94.59a3.93,3.93,0,0,0-3.93,3.92V31.06h2.71V26.55h0a5.49,5.49,0,1,1,11,0h0v4.51h2V26.55h0a5.49,5.49,0,1,1,11,0h0v4.51h2V26.55h0a5.49,5.49,0,1,1,11,0h0v4.51h2.47ZM93.37,19a5.49,5.49,0,1,1,11,0Zm12.95,0a5.49,5.49,0,1,1,11,0Zm12.94,0a5.49,5.49,0,1,1,11,0Z" transform="translate(-5 -5.5)" /></svg>
          </a>
      </footer>
  </div>
</body>
</html>

{{end}}`))

	t = template.Must(t.Parse(`
  {{define "dashboard.html"}}
  <!DOCTYPE html>
  <html lang="en" charset="utf-8">
  
  <head>
      <title>Pomerium</title>
      {{template "header.html"}}
  </head>
  
  <body>
      <div id="main">
          <div id="info-box">
            <div class="card">
                {{if .Session.Picture }}
                <img class="icon" src="{{.Session.Picture}}" alt="user image">
                {{else}}
                <svg class="icon ok" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
                      <path fill="none" d="M0 0h24v24H0V0z" />
                      <path d="M11 7h2v2h-2zm0 4h2v6h-2zm1-9C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z" />
                  </svg>
                  {{end}}

                  <form method="POST" action="/.pomerium/sign_out">
                    <section>
                        <h2>Current user</h2>
                        <p class="message">Your current session details.</p>
                        <fieldset>
                            {{if .Session.Name}}
                            <label>
                                <span>Name</span>
                                <input name="Name" type="text" class="field" value="{{.Session.Name}}" disabled>
                            </label>
                            {{else}}
                              {{if .Session.GivenName}}
                              <label>
                                  <span>Given Name</span>
                                  <input name="GivenName" type="text" class="field" value="{{.Session.GivenName}}" disabled>
                              </label>
                              {{end}}
                              {{if .Session.FamilyName}}
                              <label>
                                  <span>Family Name</span>
                                  <input name="FamilyName" type="text" class="field" value="{{.Session.FamilyName}}" disabled>
                              </label>
                              {{end}}
                            {{end}}
                            {{if .Session.Subject}}
                            <label>
                                <span>UserID</span>
                                <input name="email" type="text" class="field" value="{{.Session.Subject}}" disabled>
                            </label>                               
                            {{end}}
                            {{if .Session.Email}}
                            <label>
                                <span>Email</span>
                                <input name="email" type="email" class="field" value="{{.Session.Email}}" disabled>
                            </label>
                            {{end}}
                            {{if .Session.User}}
                            <label>
                                <span>User</span>
                                <input name="user" type="text" class="field" value="{{.Session.User}}" disabled>
                            </label>
                            {{end}}
                            {{if .Session.Groups}}
                            <label class="select">
                                <span>Groups</span>
                                <div id="group" class="field">
                                    <select name="group">
                                        {{range .Session.Groups}}
                                        <option value="{{.}}">{{.}}</option>
                                        {{end}}
                                    </select>
                                </div>
                            </label>
                            {{end}}
                            {{if .Session.Expiry}}
                            <label>
                              <span>Expiry</span>
                              <input name="session expiration" type="text" class="field" value="{{.Session.Expiry.Time}}" disabled>
                            </label>
                            {{end}}
                            {{if .Session.IssuedAt}}
                            <label>
                              <span>Issued</span>
                              <input name="session expiration" type="text" class="field" value="{{.Session.IssuedAt.Time}}" disabled>
                            </label>
                            {{end}}
                            {{if .Session.Issuer}}
                            <label>
                              <span>Issuer</span>
                              <input name="session expiration" type="text" class="field" value=" {{ .Session.Issuer}}" disabled>
                            </label>
                            {{end}}
                            {{if .Session.Audience}}
                            <label class="select">
                                <span>Audiences</span>
                                <div id="group" class="field">
                                    <select name="group">
                                        {{range .Session.Audience}}
                                        <option value="{{.}}">{{ printf "%.30s" . }}</option>
                                        {{end}}
                                    </select>
                                </div>
                            </label>
                            {{end}}

                            {{if .Session.ImpersonateEmail}}
                            <label>
                              <span>Impersonating Email</span>
                              <input name="session expiration" type="text" class="field" value="{{.Session.ImpersonateEmail}}" disabled>
                            </label>
                            {{end}}
                            {{if .Session.ImpersonateGroups}}
                            <label class="select">
                                <span>Impersonating Groups</span>
                                <div id="group" class="field">
                                    <select name="group">
                                        {{range .Session.ImpersonateGroups}}
                                        <option value="{{.}}">{{.}}</option>
                                        {{end}}
                                    </select>
                                </div>
                            </label>
                            {{end}}

                        </fieldset>
                    </section>
                    <div class="flex">
                    {{ .csrfField }}
                      <button class="button full" type="submit">Sign Out</button>
                    </div>
                  </form>


                  {{if .IsAdmin}}
                  <form method="POST" action="/.pomerium/impersonate">
                  <section>
                      <h2>Sign-in-as</h2>
                      <p class="message">Administrators can temporarily impersonate another a user.</p>
                      <fieldset>
                          <label>
                              <span>Email</span>
                              <input name="email" type="email" class="field" value="" placeholder="user@example.com">
                          </label>
                          <label>
                              <span>Group</span>
                              <input name="group" type="text" class="field" value="" placeholder="engineering">
                          </label>
                      </fieldset>
                  </section>
                  <div class="flex">
                  {{ .csrfField }}
                    <button class="button full" type="submit">Impersonate session</button>
                  </div>
                </form>
                {{ end }}
              </div>
          </div>
          <footer>
              <a href="https://www.pomerium.io" style="display: block;">
                <svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 139 30"><defs><style>.a {fill: #6e43e8;}.a,.b {fill-rule: evenodd;}.b,.c {fill: #fff;}</style></defs><title>powered-by-pomerium</title><path class="a" d="M10.6,5.5H138.4c3.09,0,5.6,2,5.6,4.39V31.11c0,2.42-2.51,4.39-5.6,4.39H10.6c-3.09,0-5.6-2-5.6-4.39V9.89C5,7.47,7.51,5.5,10.6,5.5Z" transform="translate(-5 -5.5)" /><path class="b" d="M75.4,26.62H73.94l1.13-2.79-2.25-5.69h1.54L75.78,22l1.43-3.87h1.54Zm-5.61-2.44a2.42,2.42,0,0,1-1.5-.55V24H66.78V15.56h1.51v3a2.48,2.48,0,0,1,1.5-.55c1.58,0,2.66,1.28,2.66,3.09S71.37,24.18,69.79,24.18Zm-.32-4.88a1.68,1.68,0,0,0-1.18.53v2.52a1.65,1.65,0,0,0,1.18.54c.85,0,1.44-.73,1.44-1.8S70.32,19.3,69.47,19.3Zm-8.8,4.33a2.38,2.38,0,0,1-1.5.55c-1.57,0-2.66-1.27-2.66-3.09S57.6,18,59.17,18a2.44,2.44,0,0,1,1.5.55v-3h1.52V24H60.67Zm0-3.8a1.63,1.63,0,0,0-1.17-.53c-.86,0-1.45.73-1.45,1.79s.59,1.8,1.45,1.8a1.6,1.6,0,0,0,1.17-.54Zm-9,1.68A1.69,1.69,0,0,0,53.47,23a3.55,3.55,0,0,0,1.76-.56v1.26a4.73,4.73,0,0,1-2,.46,3,3,0,0,1-3-3.13A2.87,2.87,0,0,1,53.11,18,2.66,2.66,0,0,1,55.7,21a5.53,5.53,0,0,1,0,.56Zm1.37-2.34a1.38,1.38,0,0,0-1.37,1.36h2.57A1.28,1.28,0,0,0,53.05,19.17Zm-5.34.93V24H46.2v-5.9h1.51v.59A2,2,0,0,1,49.16,18a1.65,1.65,0,0,1,.49.06v1.35a1.83,1.83,0,0,0-.53-.07A1.87,1.87,0,0,0,47.71,20.1ZM41,21.51A1.69,1.69,0,0,0,42.76,23a3.55,3.55,0,0,0,1.76-.56v1.26a4.73,4.73,0,0,1-2,.46,3,3,0,0,1-3-3.13A2.87,2.87,0,0,1,42.4,18,2.66,2.66,0,0,1,45,21a5.53,5.53,0,0,1,0,.56Zm1.37-2.34A1.38,1.38,0,0,0,41,20.53h2.57A1.28,1.28,0,0,0,42.34,19.17ZM35.7,24l-1.2-4-1.2,4H32l-2-5.9h1.51l1.19,4,1.19-4h1.37l1.19,4,1.19-4h1.51l-2,5.9Zm-9.23.14a2.94,2.94,0,0,1-3-3.09,3,3,0,1,1,6.07,0A2.94,2.94,0,0,1,26.47,24.18Zm0-4.92c-.88,0-1.49.75-1.49,1.83s.61,1.83,1.49,1.83S28,22.18,28,21.09,27.35,19.26,26.47,19.26Zm-6.62,1.87H18.49V24H17V15.93h2.87a2.61,2.61,0,1,1,0,5.2Zm-.22-4H18.49V19.9h1.14a1.38,1.38,0,1,0,0-2.75Z" transform="translate(-5 -5.5)" /><path class="c" d="M132.71,14.9A3.93,3.93,0,0,0,128.78,11H94.59a3.93,3.93,0,0,0-3.93,3.92V31.06h2.71V26.55h0a5.49,5.49,0,1,1,11,0h0v4.51h2V26.55h0a5.49,5.49,0,1,1,11,0h0v4.51h2V26.55h0a5.49,5.49,0,1,1,11,0h0v4.51h2.47ZM93.37,19a5.49,5.49,0,1,1,11,0Zm12.95,0a5.49,5.49,0,1,1,11,0Zm12.94,0a5.49,5.49,0,1,1,11,0Z" transform="translate(-5 -5.5)" /></svg>
              </a>
          </footer>
      </div>
  </body>
</html>
{{end}}`))
	return t
}
