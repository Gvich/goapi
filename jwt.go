package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"

	"net/http"
	"strings"

	"github.com/openware/rango/pkg/auth"
)

type JWTService struct {
	keys *auth.KeyStore
}

func (j *JWTService) jwtAuth(users UserRepository, h ProtectedHandler) http.HandlerFunc {
	return j.jwtAuthRoleExecutor("UserRole", users, h)
}

func (j *JWTService) jwtAuthAdmin(users UserRepository, h ProtectedHandler) http.HandlerFunc {
	return j.jwtAuthRoleExecutor("AdminRole", users, h)
}

func NewJWTService(privKeyPath, pubKeyPath string) (*JWTService, error) {
	keys, err := auth.LoadOrGenerateKeys(privKeyPath, pubKeyPath)
	if err != nil {
		return nil, err
	}

	return &JWTService{keys: keys}, nil
}

func (j *JWTService) GenearateJWT(u User) (string, error) {
	return auth.ForgeToken("empty", u.Email, "empty", 0, j.keys.PrivateKey, nil)
}

func (j *JWTService) ParseJWT(jwt string) (auth.Auth, error) {
	return auth.ParseAndValidate(jwt, j.keys.PublicKey)
}

type JWTParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u *UserService) JWT(w http.ResponseWriter, r *http.Request, jwtService *JWTService) {
	params := &JWTParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	/*if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}*/
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid login params"), w)
		return
	}

	token, err := jwtService.GenearateJWT(user)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

type ProtectedHandler func(rw http.ResponseWriter, r *http.Request, u User, users UserRepository)

func (j *JWTService) jwtAuthRoleExecutor(AccessRole string, users UserRepository, h ProtectedHandler) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		jwtAuth, err := j.ParseJWT(token)
		if err != nil {
			handleError(errors.New("unauthorized"), rw)
			return
		}
		user, err := users.Get(jwtAuth.Email)
		if err != nil {
			handleError(errors.New("unauthorized"), rw)
			return
		}
		if user.Ban {
			rw.WriteHeader(401)
			handleError(errors.New("you are banned! Reason: "+
				user.BanHistory[len(user.BanHistory)-1].Reason),
				rw)
			return
		}
		if user.Role == "UserRole" || user.Role == "" {
			if AccessRole == "AdminRole" {
				handleError(errors.New("permission denied"), rw)
				return
			}
		}

		h(rw, r, user, users)
	}
}
