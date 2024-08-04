package httpx

import (
	"net/http"
	"time"
)

// UnsetCookie adds a Set-Cookie header to the provided [http.ResponseWriter]'s
// headers with an empty Value and an Expires value of 0. The provided cookie
// name must be a valid [http.Cookie] Name. Invalid cookie names may be silently
// dropped.
func UnsetCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	}
	if v := cookie.String(); v != "" {
		w.Header().Add("Set-Cookie", v)
	}
}
