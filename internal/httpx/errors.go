package httpx

import "net/http"

// BadRequest replies to the request with an HTTP 400 bad request error.
func BadRequest(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

// InternalServerError replies to the request with an HTTP 500 internal server error.
func InternalServerError(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
