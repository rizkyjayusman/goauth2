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

type OauthUserDetailResponse struct {
	Name string `json:"name"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

func main() {

	httpClient := &http.Client{}

	http.HandleFunc("/web", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			w.Header().Set("Location", "/web/login")
			w.WriteHeader(http.StatusFound)
			return
		}

		reqUrl := fmt.Sprintf("http://localhost:8000/api/auth?token=%s", token)
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

		var filepath = path.Join("web", "views", "index.html")
		tmpl, err := template.ParseFiles(filepath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var data = map[string]interface{}{
			"username": token,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

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

	http.HandleFunc("/web/auth/oauth2/github/callback", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			fmt.Fprintf(os.Stdout, "couldn't parse the query : %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")

		reqUrl := fmt.Sprintf("http://localhost:8000/api/auth/oauth2/token?code=%s", code)
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

		var t TokenResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Location", "/web?token="+t.Token)
		w.WriteHeader(http.StatusFound)

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
		err := r.ParseForm()
		if err != nil {
			fmt.Fprintf(os.Stdout, "couldn't parse the query : %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")

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

		var t TokenResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		token := TokenResponse{
			Token: t.Token,
		}

		jsonInBytes, err := json.Marshal(token)
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not make JSON response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonInBytes)
	})

	http.HandleFunc("/api/auth", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			fmt.Fprintf(os.Stdout, "unauthorized request")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		reqUrl := fmt.Sprintf("https://github.com/user")
		req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not create HTTP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("Authorization", token)
		res, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not send HTTP request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()

		var t OauthUserDetailResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		jsonInBytes, err := json.Marshal(t)
		if err != nil {
			fmt.Fprintf(os.Stdout, "could not make JSON response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonInBytes)
	})

	http.ListenAndServe(":8000", nil)
}
