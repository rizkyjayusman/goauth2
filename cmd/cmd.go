package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	App struct {
		Name    string
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
		AccessTokenUrl string
	}

	JwtToken struct {
		SigningMethod *jwt.SigningMethodHMAC `json:"signing_method"`
		SecretKey     string                 `json:"secret_key"`
		LifeTime      time.Duration          `json:"life_time"`
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

type OauthGoogleUserDetailResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
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

type AuthResponse struct {
	Name string `json:"name"`
}

type JwtClaim struct {
	jwt.StandardClaims
	ProviderToken string `json:"provider_token"`
	ProviderName  string `json:"provider_name"`
}

var (
	oauthCfgGoogle = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:8000/web/auth/oauth2/google/callback",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
	oauthStateGoogleStr = ""
)

func New(cfg Config) (*Default, error) {
	err := godotenv.Load(".env")
	if err != nil {

	}

	cfg.App.BaseUrl = os.Getenv("APP_BASE_URL")
	cfg.App.Port = os.Getenv("APP_PORT")
	cfg.App.Name = os.Getenv("APP_NAME")

	cfg.JwtToken.SigningMethod = jwt.SigningMethodHS256
	cfg.JwtToken.SecretKey = os.Getenv("JWT_TOKEN_SECRET_KEY")
	if v, err := strconv.Atoi(os.Getenv("JWT_TOKEN_LIFETIME")); err == nil {
		cfg.JwtToken.LifeTime = time.Duration(v*1) * time.Hour
	}

	cfg.Github.ClientID = os.Getenv("OAUTH2_GITHUB_CLIENT_ID")
	cfg.Github.ClientSecret = os.Getenv("OAUTH2_GITHUB_CLIENT_SECRET")
	cfg.Github.AccessTokenUrl = os.Getenv("OAUTH2_GITHUB_ACCESS_TOKEN_URL")
	cfg.Github.LoginUrl = os.Getenv("OAUTH2_GITHUB_LOGIN_URL")
	cfg.Github.UserDetailUrl = os.Getenv("OAUTH2_GITHUB_USER_DETAIL_URL")

	cfg.Google.AccessTokenUrl = "https://www.googleapis.com/oauth2/v2/userinfo"

	oauthCfgGoogle.ClientID = os.Getenv("OAUTH2_GOOGLE_CLIENT_ID")
	oauthCfgGoogle.ClientSecret = os.Getenv("OAUTH2_GOOGLE_CLIENT_SECRET")

	oauthStateGoogleStr = uuid.NewString()

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
			w.WriteHeader(http.StatusBadRequest)
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
		log.Println("accessing /web/auth/oauth2/github/callback ...")
		err := r.ParseForm()
		if err != nil {
			log.Printf("couldn't parse the query : %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		if code == "" {
			reason := r.FormValue("error_reason")
			log.Printf("parameter code was empty cause : %v\n", reason)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		token, err := oauthCfgGoogle.Exchange(oauth2.NoContext, code)
		if err != nil {
			log.Printf("couldn't generate token from google oauth2 : %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log.Printf("google access token : %s\n" + token.AccessToken)
		log.Printf("google expired token :  %s\n" + token.Expiry.String())
		log.Printf("google refresh token : %s\n" + token.RefreshToken)

		jwtToken, err := createJwtToken(token.AccessToken, "GOOGLE", e)
		if err != nil {
			log.Printf("couldn't generate jwt token after get google oauth token : %v\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		redirectUrl := fmt.Sprintf("/web?token=%s", jwtToken)
		log.Printf("redirecting to %s ...\n", redirectUrl)
		w.Header().Set("Location", redirectUrl)
		w.WriteHeader(http.StatusFound)

		// show the error message when its return failed
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

		jwtToken, err := createJwtToken(t.Token, "GITHUB", e)
		if err != nil {
			log.Printf("couldn't generate jwt token after get github oauth token : %v\n", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		redirectUrl := fmt.Sprintf("/web?token=%s", jwtToken)
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
			URL, err := url.Parse(oauthCfgGoogle.Endpoint.AuthURL)
			if err != nil {
				log.Printf("couldn't parse google login url: %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			params := URL.Query()
			params.Add("client_id", oauthCfgGoogle.ClientID)
			params.Add("scope", strings.Join(oauthCfgGoogle.Scopes, " "))
			params.Add("redirect_uri", fmt.Sprintf("%s/web/auth/oauth2/google/callback", e.config.App.BaseUrl))
			params.Add("response_type", "code")
			params.Add("state", oauthStateGoogleStr)
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
			log.Println("unauthorized request cause token was empty")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Signing method invalid")
			} else if method != e.config.JwtToken.SigningMethod {
				return nil, fmt.Errorf("Signing method invalid")
			}

			return []byte(e.config.JwtToken.SecretKey), nil
		})

		if err != nil {
			log.Printf("couldn't parse jwt token cause : %s\n", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, ok := jwtToken.Claims.(jwt.MapClaims)
		if !ok || !jwtToken.Valid {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		provider := claims["provider_name"]
		if provider == "" {
			log.Println("unauthorized request cause provider was empty")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		providerToken := claims["provider_token"]
		if providerToken == "" {
			log.Println("unauthorized request cause provider token was empty")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var t AuthResponse
		if provider == "GITHUB" {
			reqUrl := fmt.Sprint(e.config.Github.UserDetailUrl)
			log.Printf("calling api %s ...\n", reqUrl)
			req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
			if err != nil {
				log.Printf("could not create HTTP request: %v\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("Authorization", fmt.Sprintf("token %s", providerToken))
			res, err := httpClient.Do(req)
			if err != nil {
				log.Printf("could not send HTTP request: %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer res.Body.Close()

			var resp OauthUserDetailResponse
			if res.StatusCode == http.StatusOK {
				if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
					fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			} else {
				log.Printf("status code was : %v\n", res.StatusCode)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			t.Name = resp.Name
		} else if provider == "GOOGLE" {
			reqUrl := fmt.Sprintf("%s?access_token=%s", e.config.Google.AccessTokenUrl, providerToken)
			log.Printf("calling api %s ...\n", reqUrl)
			req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
			if err != nil {
				log.Printf("could not create HTTP request: %v\n", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			req.Header.Set("Accept", "application/json")
			res, err := httpClient.Do(req)
			if err != nil {
				log.Printf("could not send HTTP request: %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer res.Body.Close()

			var resp OauthGoogleUserDetailResponse
			if res.StatusCode == http.StatusOK {
				if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
					fmt.Fprintf(os.Stdout, "could not parse JSON response: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			} else {
				log.Printf("status code was : %v\n", res.StatusCode)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			t.Name = resp.Email
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

func createJwtToken(token string, provider string, e *Default) (string, error) {
	claims := JwtClaim{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "Oauth2",
			ExpiresAt: time.Now().Add(e.config.JwtToken.LifeTime).Unix(),
		},
		ProviderToken: token,
		ProviderName:  provider,
	}

	jwtToken := jwt.NewWithClaims(
		e.config.JwtToken.SigningMethod, claims,
	)

	return jwtToken.SignedString([]byte(e.config.JwtToken.SecretKey))
}
