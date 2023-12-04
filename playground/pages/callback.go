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

	// If code is empty, check for sessionID
	if code == "" {
		sessionID := r.URL.Query().Get("session")

		if sessionID != "" {
			accessToken := getAccessTokenFromSession(sessionID)
			fmt.Println("access token from session id: ", accessToken)
			return accessToken
		}

		// Handle the case when both code and sessionID are empty
		fmt.Println("Access token not found")
		// Handle the error or redirect to login, as needed
		// http.Redirect(w, r, "/login", http.StatusSeeOther)
		// return ""
	}

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

	// If there was a code, generate a session ID and store the access token in the session
	if code != "" {
		sessionID := generateSessionID()
		setAccessTokenInSession(sessionID, accessToken)
		http.Redirect(w, r, "/dashboard?session="+sessionID, http.StatusSeeOther)
	}

	return accessToken
}

func getUserInfo(accessToken string) (map[string]interface{}, error) {
	// Set up the request to the userinfo endpoint
	req, err := http.NewRequest("GET", KindeDomain+"/oauth2/v2/user_profile", nil)
	if err != nil {
		return nil, err
	}

	// Add the access token to the request headers
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request for user profile failed with status code %d", resp.StatusCode)
	}

	// see how node JS one + is working
	// javascript - isAuthenticated check - allow user / founder to access - depends if the user exists.  if not authenticated, send to their UI / send to logout page - if something's wrong with access token ie expired - use refresh token to get the new one
	// build refresh token endpoint
	// redirect to logout

	// logout - doing the next step
	// remove cookies, redirect to KindeLogout (endpoint)
	// logout redirect - if provided logout uri, we flush everything our side and send them out to their logout

	// Parse the JSON response
	var userProfile map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userProfile)
	if err != nil {
		return nil, err
	}

	return userProfile, nil
}

// they're starting with hardcoding org plans + user plans

// get name, desc, key,
// entitlements API - get list of entitlements back
// create entitlements + plans

// if the user comes back - direct dashboard
// if its 403 error,
