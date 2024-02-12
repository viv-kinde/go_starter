package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"

	"net/http"
	"os"
)

var (
	KindeClientID     string
	KindeClientSecret string
	KindeDomain       string
	LocalDomain       string
	State             string
	Code              string
	RedirectURL       string
	sessionMutex      sync.Mutex

	sessions = make(map[string]string)
)

type OAuthConfig struct {
	TokenURL     string
	Code         string
	ClientID     string
	ClientSecret string
	GrantType    string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func generateSessionID() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "default_session_id"
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func getAccessTokenFromSession(sessionID string) string {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	return sessions[sessionID]
}

func setAccessTokenInSession(sessionID, accessToken string) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	sessions[sessionID] = accessToken
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("partials/logged-out.tmpl", "templates/layout.tmpl", "partials/header.tmpl", "partials/footer.tmpl"))

	err := tmpl.ExecuteTemplate(w, "layout.tmpl", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {

	tmpl := template.Must(template.ParseFiles("partials/logged-in.tmpl", "templates/layout.tmpl", "partials/header.tmpl", "partials/footer.tmpl"))

	accessToken := getAccessToken(w, r)

	userInfo, err := getUserInfo(accessToken)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	err = tmpl.ExecuteTemplate(w, "layout.tmpl", userInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func genRandState() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func readCookie(w http.ResponseWriter, req *http.Request) *http.Cookie {
	var cookie, _ = req.Cookie("kindeState")

	return cookie
}

func kindeAuth(w http.ResponseWriter, r *http.Request) {
	prompt := "login"
	if strings.Contains(r.URL.Path, "/register") {
		prompt = "create"
	}

	kindeState := &http.Cookie{
		Name:     "kindeState",
		Value:    State,
		Expires:  time.Now().Add(time.Minute * 60),
		HttpOnly: false,
	}

	http.SetCookie(w, kindeState)

	authURL := fmt.Sprintf("%s/oauth2/auth"+
		"?response_type=code"+
		"&prompt=%s"+
		"&client_id=%s"+
		"&redirect_uri=%s/dashboard"+
		"&scope=openid%%20profile%%20email"+
		"&state=%s", KindeDomain, prompt, KindeClientID, LocalDomain, State)

	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func main() {
	envPath := "../../.env"
	envPath = os.ExpandEnv(envPath)
	err := godotenv.Load(envPath)
	if err != nil {
		fmt.Println("Error loading .env file:", err)
	}

	KindeClientID = os.Getenv("KINDE_CLIENT_ID")
	KindeClientSecret = os.Getenv("KINDE_CLIENT_SECRET")
	KindeDomain = os.Getenv("KINDE_ISSUER_URL")
	LocalDomain = os.Getenv("KINDE_SITE_URL")
	RedirectURL = os.Getenv("KINDE_POST_LOGOUT_REDIRECT_URL")

	State, _ = genRandState()

	http.HandleFunc("/", indexHandler)

	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/login", kindeAuth)
	http.HandleFunc("/register", kindeAuth)
	http.HandleFunc("/logout", logoutHandler)

	fs := http.FileServer(http.Dir("styles"))
	http.Handle("/styles/", http.StripPrefix("/styles/", fs))

	if err := http.ListenAndServe(":3000", nil); err != nil {
		panic(err)
	}
}
