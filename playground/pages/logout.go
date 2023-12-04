package main

import (
	"fmt"
	"net/http"
)

func logoutHandler(w http.ResponseWriter, r *http.Request) {

	cookies := r.Cookies()

	for _, cookie := range cookies {
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
	}

	logoutURL := fmt.Sprintf("%s/logout?redirect=%s", KindeDomain, RedirectURL)

	http.Redirect(w, r, logoutURL, http.StatusSeeOther)
}
