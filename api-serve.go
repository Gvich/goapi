//user_repository.go
package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

func getCakeHandler(w http.ResponseWriter, r *http.Request, u User, users UserRepository) {
	w.Write([]byte(u.FavoriteCake))
}
func getMeHandler(w http.ResponseWriter, r *http.Request, u User, users UserRepository) {
	w.Write([]byte(u.FavoriteCake))
	w.Write([]byte(u.Email))
}
func getEmailHandler(w http.ResponseWriter, r *http.Request, u User, users UserRepository) {
	w.Write([]byte(u.Email))
}
func wrapJwt(
	jwt *JWTService,
	f func(http.ResponseWriter, *http.Request, *JWTService),
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		f(rw, r, jwt)
	}
}
func (uServ UserService) updateCakeHandler(w http.ResponseWriter, r *http.Request, u User, users UserRepository) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if err := validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	newCake := User{
		Email:          params.Email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
	}
	err = uServ.repository.Update(params.Email, newCake)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("cake updated"))
}
func (uServ UserService) updateEmailHandler(w http.ResponseWriter, r *http.Request, u User, users UserRepository) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if err := validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	email := params.Email
	newEmail := User{
		Email:          email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
	}

	uServ.repository.Delete(u.Email)
	err = uServ.repository.Add(email, newEmail)

	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("email updated"))
}
func (uServ UserService) updatePasswordHandler(w http.ResponseWriter, r *http.Request, u User, users UserRepository) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if err := validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	newCake := User{
		Email:          params.Email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
	}
	err = uServ.repository.Update(params.Email, newCake)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("password updated"))
}
func (uServ *UserService) addAdmin() error {
	CAKE_ADMIN_EMAIL := os.Getenv("CAKE_ADMIN_EMAIL")
	CAKE_ADMIN_PASSWORD := os.Getenv("CAKE_ADMIN_PASSWORD")
	passwordDigest := md5.New().Sum([]byte(CAKE_ADMIN_PASSWORD))
	admin := User{
		Email:          CAKE_ADMIN_EMAIL,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   "AdminCake",
		Role:           "AdminRole",
		Ban:            false,
		BanHistory:     History{},
	}
	err := uServ.repository.Add(admin.Email, admin)
	if err != nil {
		return err
	}
	return nil
}
func main() {
	os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
	os.Setenv("CAKE_ADMIN_PASSWORD", "adminadmin")

	r := mux.NewRouter()

	users := NewInMemoryUserStorage()
	userService := UserService{
		repository: users,
	}

	jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
	if err != nil {
		panic(err)
	}

	r.HandleFunc("/admin/ban", logRequest(jwtService.jwtAuthAdmin(userService.repository, banUserHandler))).Methods(http.MethodPost)
	r.HandleFunc("/admin/unban", logRequest(jwtService.jwtAuthAdmin(userService.repository, unbanUserHandler))).Methods(http.MethodPost)
	r.HandleFunc("/admin/inspect", logRequest(jwtService.jwtAuthAdmin(userService.repository, inspectHandler))).Methods(http.MethodGet)

	r.HandleFunc("/user/me", logRequest(jwtService.jwtAuth(users, getMeHandler))).Methods(http.MethodGet)
	r.HandleFunc("/user/favorite_cake", logRequest(jwtService.jwtAuth(users, userService.updateCakeHandler))).Methods(http.MethodPost)
	r.HandleFunc("/user/email", logRequest(jwtService.jwtAuth(users, userService.updateEmailHandler))).Methods(http.MethodPost)
	r.HandleFunc("/user/password", logRequest(jwtService.jwtAuth(users, userService.updatePasswordHandler))).Methods(http.MethodPost)

	r.HandleFunc("/cake", logRequest(jwtService.jwtAuth(users, getCakeHandler))).Methods(http.MethodGet)
	r.HandleFunc("/user/register", logRequest(userService.Register)).Methods(http.MethodPost)
	r.HandleFunc("/user/jwt", logRequest(wrapJwt(jwtService, userService.JWT))).Methods(http.MethodPost)

	userService.addAdmin()
	srv := http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	log.Printf("Server stared, press cntrl + C to stop ")
	errr := srv.ListenAndServe()
	if errr != nil {
		log.Println("Server exited with error:", err)
	}
	log.Println("Good bye :)")
}
