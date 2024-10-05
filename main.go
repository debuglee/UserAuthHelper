package main

import (
	"net/http"

	"github.com/debuglee/UserAuthHelper/auth_module"

	"github.com/gorilla/mux"
)

func main() {
	dsn := "root:root@tcp(127.0.0.1:8889)/authhelper?charset=utf8mb4&parseTime=True&loc=Local"
	auth_module.InitDB(dsn)

	r := mux.NewRouter()

	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		auth_module.Login(w, r, auth_module.DB)
	}).Methods("POST")

	r.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		auth_module.Logout(w, r, auth_module.DB)
	}).Methods("POST")

	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		auth_module.Register(w, r, auth_module.DB)
	}).Methods("POST")

	// Import the AuthMiddleware from auth_module
	r.Handle("/protected-endpoint", auth_module.AuthMiddleware(http.HandlerFunc(SomeHandler)))

	http.ListenAndServe(":8899", r)
}

func SomeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("You have accessed a protected endpoint!"))
}
