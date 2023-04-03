package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path"
)

const (
	clientID     = "clntid"
	clientSecret = "clntscrt"
)

type OAuthAccessResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type OauthRequestResponse struct {
	RedirectUrl string `json:"redirect_url"`
}

func main() {

	http.HandleFunc("/web/login", func(w http.ResponseWriter, r *http.Request) {
		var filepath = path.Join("web", "views", "login.html")
		var tmpl, err = template.ParseFiles(filepath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var data = map[string]interface{}{
			"oauth_github_client_id": clientID,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	httpClient := &http.Client{}

	http.HandleFunc("/web/auth/oauth2/github", func(w http.ResponseWriter, r *http.Request) {
		reqUrl := fmt.Sprintf("http://localhost:8000/api/auth/oauth2/request")
		req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
		if err != nil {
			fmt.Fprintf(os.Stdout, "couldn't parse the query : %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("accept", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not send HTTP request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer res.Body.Close()

		var t OauthRequestResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Location", t.RedirectUrl)
		w.WriteHeader(http.StatusFound)
	})

	http.HandleFunc("/web/auth/oauth2/google/callback", func(w http.ResponseWriter, r *http.Request) {
		// do post to /api/auth/oauth2/token
		// get a token if success
		// show the error message when its return failed
	})

	http.HandleFunc("/api/auth/oauth2/request", func(w http.ResponseWriter, r *http.Request) {
		resp := OauthRequestResponse{
			RedirectUrl: fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s", clientID),
		}

		jsonInBytes, err := json.Marshal(resp)
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not make JSON response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonInBytes)
		//
	})

	http.HandleFunc("/api/auth/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		// retrieve the code
		// request token to github/google/etc
		// store on db
		// generate the backend token
	})

	http.HandleFunc("/callback/oauth/github", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			fmt.Fprintf(os.Stdout, "couldn't parse the query : %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		fmt.Println("Code : >> ", code)

		reqUrl := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s", clientID, clientSecret, code)
		req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not create HTTP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("accept", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not send HTTP request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()

		var t OAuthAccessResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Location", "/welcome.html?access_token="+t.AccessToken)
		w.WriteHeader(http.StatusFound)
	})

	http.ListenAndServe(":8000", nil)
}
