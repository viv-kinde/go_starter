package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func getAccessToken(w http.ResponseWriter, r *http.Request) string {
	// Get the authorization code from the query parameters
	code := r.URL.Query().Get("code")

	// Token endpoint URL
	tokenURL := fmt.Sprintf("%s/oauth2/token", KindeDomain)

	// Build the request payload
	payload := url.Values{}
	payload.Set("grant_type", "authorization_code")
	payload.Set("client_id", KindeClientID)
	payload.Set("client_secret", KindeClientSecret)
	payload.Set("code", code)
	payload.Set("redirect_uri", LocalDomain+"/dashboard")

	// make POST req to tokenURL endpoint -> send payload
	res, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(payload.Encode()))
	if err != nil {
		fmt.Println("Error making the request:", err)
		// return
	}
	defer res.Body.Close()

	// read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Error reading the response body:", err)
		// return
	}

	// check status code for errs
	if res.StatusCode != http.StatusOK {
		fmt.Println("Request failed with status:", res.Status)
		// return
	}

	// parse response body -> to get access token
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error parsing response body:", err)
		// return
	}

	accessToken, ok := response["access_token"].(string)
	if !ok {
		fmt.Println("Access token not found in the response")
		// return
	}

	return accessToken

	// http.Redirect(w, r, "http://localhost:3000/dashboard", http.StatusSeeOther)

	// fmt.Println("Access Token:", accessToken)
}
