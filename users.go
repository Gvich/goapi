package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
)

type User struct {
	Email          string
	PasswordDigest string
	FavoriteCake   string
	Role           string
	BanHistory     History
	Ban            bool
}
type UserRepository interface {
	Add(string, User) error
	Get(string) (User, error)
	Update(string, User) error
	Delete(string) (User, error)
}

type UserService struct {
	repository UserRepository
}

type UserRegisterParams struct {
	// If it looks strange, read about golang struct tags
	Email        string `json:"email"`
	Password     string `json:"password"`
	FavoriteCake string `json:"favorite_cake"`
}

func validateRegisterParams(p *UserRegisterParams) error {
	// 1. Email is valid
	if p.Email == "" {
		return errors.New("The email field is required!")
	}
	//regexpEmail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	//regexpEmail.MatchString(p.Email)
	_, err := mail.ParseAddress(p.Email)
	if err != nil {
		return errors.New("The email field should be a valid email address!")
	}
	// 2. Password at least 8 symbols
	if len(p.Password) < 8 {
		return errors.New("Password at least 8 symbols")
	}
	// 3. Favorite cake not empty
	if p.FavoriteCake == "" {
		return errors.New("Favorite cake should not be empty")
	}
	// 4. Favorite cake only alphabetic
	for _, c := range p.FavoriteCake {
		if !((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) {
			return errors.New("Favorite cake should be only alphabetic")
		}
	}
	return nil
}

func handleError(err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnprocessableEntity)
	w.Write([]byte(err.Error()))
}

func (u *UserService) Register(w http.ResponseWriter, r *http.Request) {

	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	/*if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}*/
	if err := validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	newUser := User{
		Email:          params.Email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
	}
	err = u.repository.Add(params.Email, newUser)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered"))

}
