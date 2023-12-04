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

// Function to generate a unique session ID
func generateSessionID() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Handle the error, panic, or return a default value
		return "default_session_id"
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func getAccessTokenFromSession(sessionID string) string {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	return sessions[sessionID]
}

// Function to set the access token in the session
func setAccessTokenInSession(sessionID, accessToken string) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	sessions[sessionID] = accessToken
}

// takes HTTP response (w) and HTTP request (r) - intended to handle requests to ("/")
func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("partials/logged-out.tmpl", "templates/layout.tmpl", "partials/header.tmpl", "partials/footer.tmpl"))

	err := tmpl.ExecuteTemplate(w, "layout.tmpl", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// parses HTML template files
	// template.Must - panics if there's err during parsing
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
	// read cookie
	var cookie, _ = req.Cookie("kindeState")
	// if err == nil {
	//     var cookievalue = cookie.Value
	//     w.Write([]byte(cookievalue))
	// }

	return cookie
}

func kindeAuth(w http.ResponseWriter, r *http.Request) {
	startPage := "login"
	if strings.Contains(r.URL.Path, "/register") {
		startPage = "registration"
	}

	// set state in cookie
	kindeState := &http.Cookie{
		Name:     "kindeState",
		Value:    State,
		Expires:  time.Now().Add(time.Minute * 60),
		HttpOnly: false,
	}

	http.SetCookie(w, kindeState)
	// first cookie ^^

	authURL := fmt.Sprintf("%s/oauth2/auth"+
		"?response_type=code"+
		"&start_page=%s"+
		"&client_id=%s"+
		"&redirect_uri=%s/dashboard"+
		"&scope=openid%%20profile%%20email"+
		"&state=%s", KindeDomain, startPage, KindeClientID, LocalDomain, State)

	http.Redirect(w, r, authURL, http.StatusSeeOther)

	// cookieAmount := readCookie(w, r)
	// accessToken := getAccessToken(w, r)
	// fmt.Println(accessToken)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookies := r.Cookies()

	// Iterate through the cookies and set MaxAge to a negative value to delete them
	for _, cookie := range cookies {
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
	}

	// http.Redirect(w, r, "/login", http.StatusSeeOther)

}

// Handling the callback
// send {client_id: 102938, client_secret: 123}

// logout - redirect to kinde url /logout
// kill anything / storage on their side

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

	State, _ = genRandState()

	http.HandleFunc("/", indexHandler)

	// define user
	// if user comes back authenticated (isAuthenticated()) - then show:
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/login", kindeAuth)
	http.HandleFunc("/register", kindeAuth)
	http.HandleFunc("/logout", logoutHandler)

	// http.HandleFunc("/logout", kindeAuth)

	// Serve CSS files
	fs := http.FileServer(http.Dir("styles"))
	http.Handle("/styles/", http.StripPrefix("/styles/", fs))

	// Start the HTTP server
	if err := http.ListenAndServe(":3000", nil); err != nil {
		panic(err)
	}
}
