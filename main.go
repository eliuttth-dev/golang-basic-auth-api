package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"strings"
  "encoding/base64"
	"github.com/gorilla/mux"
)

const (
	validUsername = "admin"
	validPassword = "password123"
)

func BasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		authParts := strings.Split(authHeader, " ")
		if len(authParts) != 2 || authParts[0] != "Basic" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		decoded, err := basicAuthDecode(authParts[1])
		if err != nil {
			http.Error(w, "Invalid base64 encoding", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(decoded, ":")
		if len(parts) != 2 {
			http.Error(w, "Invalid credentials format", http.StatusUnauthorized)
			return
		}

		if subtle.ConstantTimeCompare([]byte(parts[0]), []byte(validUsername)) == 1 &&
			subtle.ConstantTimeCompare([]byte(parts[1]), []byte(validPassword)) == 1 {
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		}
	})
}

func basicAuthDecode(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("This is a protected endpoint"))
}

func main() {
	r := mux.NewRouter()
	r.Handle("/protected", BasicAuth(http.HandlerFunc(ProtectedEndpoint)))

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

