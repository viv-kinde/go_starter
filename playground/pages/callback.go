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

	code := r.URL.Query().Get("code")

	if code == "" {
		sessionID := r.URL.Query().Get("session")

		if sessionID != "" {
			accessToken := getAccessTokenFromSession(sessionID)
			return accessToken
		}

		fmt.Println("Access token not found")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return ""
	}

	tokenURL := fmt.Sprintf("%s/oauth2/token", KindeDomain)

	payload := url.Values{}
	payload.Set("grant_type", "authorization_code")
	payload.Set("client_id", KindeClientID)
	payload.Set("client_secret", KindeClientSecret)
	payload.Set("code", code)
	payload.Set("redirect_uri", LocalDomain+"/dashboard")

	res, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(payload.Encode()))
	if err != nil {
		fmt.Println("Error making the request:", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Error reading the response body:", err)
	}

	if res.StatusCode != http.StatusOK {
		fmt.Println("Request failed with status:", res.Status)
	}

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error parsing response body:", err)
	}

	accessToken, ok := response["access_token"].(string)
	if !ok {
		fmt.Println("Access token not found in the response")
	}

	if code != "" {
		sessionID := generateSessionID()
		setAccessTokenInSession(sessionID, accessToken)
		http.Redirect(w, r, "/dashboard?session="+sessionID, http.StatusSeeOther)
	}

	return accessToken
}

type UserInfo struct {
	Email      string  `json:"email"`
	FamilyName string  `json:"family_name"`
	GivenName  string  `json:"given_name"`
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Picture    string  `json:"picture"`
	Sub        string  `json:"sub"`
	UpdatedAt  float64 `json:"updated_at"`
	Initials   string
}

func getInitials(familyName, givenName string) string {
	familyInitial := string(familyName[0])
	givenInitial := string(givenName[0])

	return familyInitial + givenInitial
}

func getUserInfo(accessToken string) (UserInfo, error) {

	req, err := http.NewRequest("GET", KindeDomain+"/oauth2/v2/user_profile", nil)
	if err != nil {
		return UserInfo{}, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return UserInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return UserInfo{}, fmt.Errorf("request for user profile failed with status code %d", resp.StatusCode)
	}

	var userProfile UserInfo
	err = json.NewDecoder(resp.Body).Decode(&userProfile)
	if err != nil {
		return UserInfo{}, err
	}

	userProfile.Initials = getInitials(userProfile.GivenName, userProfile.FamilyName)

	return userProfile, nil
}