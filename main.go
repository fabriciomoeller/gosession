package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
)

type User struct {
	Username string
	Password string
}

var session *scs.SessionManager

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("templates/login.html")
	t.Execute(w, nil)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("templates/profile.html")
	username := session.GetString(r.Context(), "username")
	fmt.Print(username)
	t.Execute(w, username)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("templates/index.html")
	t.Execute(w, nil)
}

func LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if !(username == "admin" && password == "admin") {
		t, _ := template.ParseFiles("templates/login.html")
		t.Execute(w, "Invalid username or password")
	}

	session.Put(r.Context(), "username", username)
	http.Redirect(w, r, "/profile", http.StatusSeeOther)

}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session.Destroy(r.Context())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func SecureMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !session.Exists(r.Context(), "username") {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func init() {
	session = scs.New()
	session.Lifetime = 24 * time.Hour
	session.Cookie.Persist = true
	session.Cookie.SameSite = http.SameSiteLaxMode
	session.Cookie.Secure = true
}

func main() {

	mux := http.NewServeMux()

	fmt.Println("Servidor porta 8080")
	mux.HandleFunc("/", IndexHandler)
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/profile", SecureMiddleware(ProfileHandler))
	mux.HandleFunc("/signin", LoginPostHandler)
	mux.HandleFunc("/logout", LogoutHandler)
	http.ListenAndServe(":8080", session.LoadAndSave(mux))
}
