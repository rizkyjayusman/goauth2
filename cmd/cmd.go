package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

type Config struct {
	App struct {
		BaseUrl string
		Port    string
	}

	Github struct {
		ClientID     string
		ClientSecret string

		AccessTokenUrl string
		LoginUrl       string

		UserDetailUrl string
	}

	Google struct {
		LoginUrl    string
		RedirectURL string

		ClientID     string
		ClientSecret string
		Scopes       []string
	}
}

type Default struct {
	config Config
}

type OAuthAccessResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type OauthRequestResponse struct {
	RedirectUrl string `json:"redirect_url"`
}

type OauthUserDetailResponse struct {
	Login             string `json:"login"`
	ID                uint64 `json:"id"`
	NodeID            string `json:"node_id"`
	AvatarUrl         string `json:"avatar_url"`
	GravatarID        string `json:"gravatar_id"`
	Url               string `json:"url"`
	HtmlUrl           string `json:"html_url"`
	FollowerUrl       string `json:"follower_url"`
	FollowingUrl      string `json:"following_url"`
	GistsUrl          string `json:"gists_url"`
	StarredUrl        string `json:"starred_url"`
	SubscriptionsUrl  string `json:"subscriptions_url"`
	OrganizationsUrl  string `json:"organizations_url"`
	ReposUrl          string `json:"repos_url"`
	EventsUrl         string `json:"events_url"`
	ReceivedEventsUrl string `json:"received_events_url"`
	Type              string `json:"type"`
	SiteAdmin         bool   `json:"site_admin"`
	Name              string `json:"name"`
	Company           string `json:"company"`
	Blog              string `json:"blog"`
	Location          string `json:"location"`
	Email             string `json:"email"`
	Hireable          bool   `json:"hireable"`
	Bio               string `json:"bio"`
	TwitterUsername   string `json:"twitter_username"`
	PublicRepos       int    `json:"public_repos"`
	PublicGists       int    `json:"public_gists"`
	Followers         int    `json:"followers"`
	Following         int    `json:"following"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

func New(cfg Config) (*Default, error) {
	err := godotenv.Load(".env")
	if err != nil {

	}

	cfg.App.BaseUrl = os.Getenv("APP_BASE_URL")
	cfg.App.Port = os.Getenv("APP_PORT")

	cfg.Github.ClientID = os.Getenv("OAUTH2_GITHUB_CLIENT_ID")
	cfg.Github.ClientSecret = os.Getenv("OAUTH2_GITHUB_CLIENT_SECRET")
	cfg.Github.AccessTokenUrl = os.Getenv("OAUTH2_GITHUB_ACCESS_TOKEN_URL")
	cfg.Github.LoginUrl = os.Getenv("OAUTH2_GITHUB_LOGIN_URL")
	cfg.Github.UserDetailUrl = os.Getenv("OAUTH2_GITHUB_USER_DETAIL_URL")

	cfg.Google.ClientID = os.Getenv("OAUTH2_GOOGLE_CLIENT_ID")
	cfg.Google.ClientSecret = os.Getenv("OAUTH2_GOOGLE_CLIENT_SECRET")
	cfg.Google.LoginUrl = os.Getenv("OAUTH2_GOOGLE_LOGIN_URL")
	cfg.Google.Scopes = []string{"https://www.googleapis.com/auth/userinfo.email"}

	e := &Default{config: cfg}
	return e, nil
}

func (e *Default) Execute() {
	httpClient := &http.Client{}

	http.HandleFunc("/web", func(w http.ResponseWriter, r *http.Request) {
		log.Println("accessing /web ...")
		token := r.URL.Query().Get("token")
		if token == "" {
			log.Println("redirecting to /web/login cause param token is empty.")
			w.Header().Set("Location", "/web/login")
			w.WriteHeader(http.StatusFound)
			return
		}

		reqUrl := fmt.Sprintf("%s/api/auth?token=%s", e.config.App.BaseUrl, token)
		log.Printf("calling api %s ...\n", reqUrl)
		req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
		if err != nil {
			log.Printf("couldn't parse the query : %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("accept", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("could not send HTTP request: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer res.Body.Close()

		var t OauthUserDetailResponse
		if res.StatusCode == http.StatusOK {
			if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
				log.Printf("could not parse JSON response: %v\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		} else {
			log.Printf("status code was : %v\n", res.StatusCode)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var filepath = path.Join("web", "views", "index.html")
		tmpl, err := template.ParseFiles(filepath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var data = map[string]interface{}{
			"username": t.Name,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/web/login", func(w http.ResponseWriter, r *http.Request) {
		log.Println("accessing /web/login ...")
		var filepath = path.Join("web", "views", "login.html")
		var tmpl, err = template.ParseFiles(filepath)
		if err != nil {
			log.Printf("couldn't parse file into html template : %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var data = map[string]interface{}{
			"oauth_github_client_id": e.config.Github.ClientID,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			log.Printf("couldn't parse file into html template : %s\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/web/auth/oauth2/google", func(w http.ResponseWriter, r *http.Request) {
		log.Println("accessing /web/auth/oauth2/google ...")
		reqUrl := fmt.Sprintf("%s/api/auth/oauth2/request?provider=GOOGLE", e.config.App.BaseUrl)
		log.Printf("calling api %s ...\n", reqUrl)
		req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
		if err != nil {
			log.Printf("couldn't parse the query : %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("accept", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("could not send HTTP request: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer res.Body.Close()

		var t OauthRequestResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			log.Printf("could not parse JSON response: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Location", t.RedirectUrl)
		w.WriteHeader(http.StatusFound)
	})

	http.HandleFunc("/web/auth/oauth2/github", func(w http.ResponseWriter, r *http.Request) {
		log.Println("accessing /web/auth/oauth2/github ...")
		reqUrl := fmt.Sprintf("%s/api/auth/oauth2/request?provider=GITHUB", e.config.App.BaseUrl)
		log.Printf("calling api %s ...\n", reqUrl)
		req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
		if err != nil {
			log.Printf("couldn't parse the query : %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("accept", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("could not send HTTP request: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer res.Body.Close()

		var t OauthRequestResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			log.Printf("could not parse JSON response: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Location", t.RedirectUrl)
		w.WriteHeader(http.StatusFound)
	})

	http.HandleFunc("/web/auth/oauth2/google/callback", func(w http.ResponseWriter, r *http.Request) {
		// TODO :: handle callback
	})

	http.HandleFunc("/web/auth/oauth2/github/callback", func(w http.ResponseWriter, r *http.Request) {
		log.Println("accessing /web/auth/oauth2/github/callback ...")
		err := r.ParseForm()
		if err != nil {
			log.Printf("couldn't parse the query : %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")

		reqUrl := fmt.Sprintf("%s/api/auth/oauth2/token?code=%s", e.config.App.BaseUrl, code)
		log.Printf("calling api %s ...\n", reqUrl)
		req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
		if err != nil {
			log.Printf("couldn't parse the query : %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("accept", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("could not send HTTP request: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer res.Body.Close()

		var t TokenResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			log.Printf("could not parse JSON response: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		redirectUrl := fmt.Sprintf("/web?token=%s", t.Token)
		log.Printf("redirecting to %s ...\n", redirectUrl)
		w.Header().Set("Location", redirectUrl)
		w.WriteHeader(http.StatusFound)

		// show the error message when its return failed
	})

	http.HandleFunc("/api/auth/oauth2/request", func(w http.ResponseWriter, r *http.Request) {
		log.Println("accessing /api/auth/oauth2/request ...")

		provider := r.URL.Query().Get("provider")
		if provider == "" {
			log.Println("redirecting to /web/login cause param provider is empty.")
			w.Header().Set("Location", "/web/login")
			w.WriteHeader(http.StatusFound)
			return
		}

		var redirectUrl string
		if provider == "GITHUB" {
			redirectUrl = fmt.Sprintf("%s?client_id=%s", e.config.Github.LoginUrl, e.config.Github.ClientID)
		} else if provider == "GOOGLE" {
			URL, err := url.Parse(e.config.Google.LoginUrl)
			if err != nil {
				log.Printf("couldn't parse google login url: %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			params := URL.Query()
			params.Add("client_id", e.config.Google.ClientID)
			params.Add("scope", strings.Join(e.config.Google.Scopes, " "))
			params.Add("redirect_uri", fmt.Sprintf("%s/web/auth/oauth2/google/callback", e.config.App.BaseUrl))
			params.Add("response_type", "code")
			params.Add("state", uuid.NewString())
			URL.RawQuery = params.Encode()
			redirectUrl = URL.String()
			log.Printf("google oauth2 redirect url : %s\n", redirectUrl)
		} else {
			log.Printf("provider was not valid : %s\n", provider)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp := OauthRequestResponse{
			RedirectUrl: redirectUrl,
		}

		jsonInBytes, err := json.Marshal(resp)
		if err != nil {
			log.Printf("could not make JSON response: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonInBytes)
	})

	http.HandleFunc("/api/auth/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("accessing /api/auth/oauth2/token ...")
		err := r.ParseForm()
		if err != nil {
			log.Printf("couldn't parse the query : %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")

		reqUrl := fmt.Sprintf("%s?client_id=%s&client_secret=%s&code=%s", e.config.Github.AccessTokenUrl,
			e.config.Github.ClientID, e.config.Github.ClientSecret, code)
		log.Printf("calling api %s ...\n", reqUrl)
		req, err := http.NewRequest(http.MethodPost, reqUrl, nil)
		if err != nil {
			log.Printf("could not create HTTP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("accept", "application/json")

		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("could not send HTTP request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()

		var t OAuthAccessResponse
		if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
			log.Printf("could not parse JSON response: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log.Printf("parsing response to get token github oauth2 : %s\n", t.AccessToken)
		token := TokenResponse{
			Token: t.AccessToken,
		}

		jsonInBytes, err := json.Marshal(token)
		if err != nil {
			log.Printf("could not make JSON response: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonInBytes)
	})

	http.HandleFunc("/api/auth", func(w http.ResponseWriter, r *http.Request) {
		log.Println("accessing /api/auth ...")

		token := r.URL.Query().Get("token")
		if token == "" {
			log.Println("unauthorized request")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		reqUrl := fmt.Sprint(e.config.Github.UserDetailUrl)
		log.Printf("calling api %s ...\n", reqUrl)
		req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
		if err != nil {
			log.Printf("could not create HTTP request: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("could not send HTTP request: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()

		var t OauthUserDetailResponse
		if res.StatusCode == http.StatusOK {
			if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
				fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		} else {

			log.Printf("status code was : %v\n", res.StatusCode)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		jsonInBytes, err := json.Marshal(t)
		if err != nil {
			log.Printf("could not make JSON response: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonInBytes)
	})

	http.ListenAndServe(fmt.Sprintf(":%s", e.config.App.Port), nil)
}
