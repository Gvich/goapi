package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type parsedResponse struct {
	status int
	body   []byte
}

func createRequester(t *testing.T) func(req *http.Request, err error) parsedResponse {
	return func(req *http.Request, err error) parsedResponse {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		resp, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		return parsedResponse{res.StatusCode, resp}
	}
}
func prepareParams(t *testing.T, params map[string]interface{}) io.
	Reader {
	body, err := json.Marshal(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	return bytes.NewBuffer(body)
}
func newTestUserService() *UserService {
	return &UserService{
		repository: NewInMemoryUserStorage(),
	}
}

func assertStatus(t *testing.T, expected int, r parsedResponse) {
	if r.status != expected {
		t.Errorf("Unexpected response status. Expected: %d,actual: %d", expected, r.status)
	}
}
func assertBody(t *testing.T, expected string, r parsedResponse) {
	actual := string(r.body)
	if actual != expected {
		t.Errorf("Unexpected response body. Expected: %s,actual: %s", expected, actual)
	}
}
func getBody(r parsedResponse) string {
	a := string(r.body)
	return a
}
func TestUsers_JWT(t *testing.T) {
	doRequest := createRequester(t)
	t.Run("user does not exist", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})
	t.Run("wrong password", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		params2 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "someAnotherpass",
			"favorite_cake": "cheesecake",
		}

		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, params2)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})
	t.Run("newjwtservice error", func(t *testing.T) {
		_, err := NewJWTService("", "pjnskfg")
		if err == nil {
			t.Error("pub and priv keys are okay")
		}
	})

	t.Run("user register", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 201, resp)
		assertBody(t, "registered", resp)
	})

	t.Run("user cake unauthorized", func(t *testing.T) {
		u := newTestUserService()
		users := NewInMemoryUserStorage()

		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(j.jwtAuth(users, getCakeHandler))

		ts3 := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "",
		}
		doRequest(http.NewRequest(http.MethodPost, ts3.URL+"/user/register", prepareParams(t, params)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/cake", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "unauthorized", resp)
	})
	t.Run("cheesecake", func(t *testing.T) {
		u := newTestUserService()
		//users := NewInMemoryUserStorage()

		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(j.jwtAuth(u.repository, getCakeHandler))
		ts2 := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		ts3 := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		params2 := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		doRequest(http.NewRequest(http.MethodPost, ts3.URL+"/user/register", prepareParams(t, params)))
		temp := doRequest(http.NewRequest(http.MethodPost, ts2.URL, prepareParams(t, params2)))
		req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
		req.Header.Add("Authorization", "Bearer "+string(getBody(temp)))
		resp := doRequest(req, err)

		assertStatus(t, 200, resp)
		assertBody(t, "cheesecake", resp)
	})
	t.Run("emailHandler", func(t *testing.T) {
		u := newTestUserService()
		//users := NewInMemoryUserStorage()

		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(j.jwtAuth(u.repository, getEmailHandler))
		ts2 := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		ts3 := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		params2 := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		doRequest(http.NewRequest(http.MethodPost, ts3.URL+"/user/register", prepareParams(t, params)))
		temp := doRequest(http.NewRequest(http.MethodPost, ts2.URL, prepareParams(t, params2)))
		req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
		req.Header.Add("Authorization", "Bearer "+string(getBody(temp)))
		resp := doRequest(req, err)

		assertStatus(t, 200, resp)
		assertBody(t, "test@mail.com", resp)
	})
	t.Run("udate cakeHandler", func(t *testing.T) {
		u := newTestUserService()
		//users := NewInMemoryUserStorage()

		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		ts := httptest.NewServer(http.HandlerFunc(u.Register))

		ts3 := httptest.NewServer(j.jwtAuth(u.repository, u.updateCakeHandler))

		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		params2 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "newcakemufin",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))

		Useruser, _ := u.repository.Get("test@mail.com")
		adminJwt, _ := j.GenearateJWT(Useruser)

		req, err := http.NewRequest(http.MethodGet, ts3.URL, prepareParams(t, params2))
		req.Header.Add("Authorization", "Bearer "+string(adminJwt))
		resp := doRequest(req, err)

		assertStatus(t, 200, resp)
		assertBody(t, "cake updated", resp)
	})
	t.Run("udate passwordHandler", func(t *testing.T) {
		u := newTestUserService()
		//users := NewInMemoryUserStorage()

		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		ts := httptest.NewServer(http.HandlerFunc(u.Register))

		ts3 := httptest.NewServer(j.jwtAuth(u.repository, u.updatePasswordHandler))

		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		params2 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somenewpass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))

		Useruser, _ := u.repository.Get("test@mail.com")
		adminJwt, _ := j.GenearateJWT(Useruser)

		req, err := http.NewRequest(http.MethodGet, ts3.URL, prepareParams(t, params2))
		req.Header.Add("Authorization", "Bearer "+string(adminJwt))
		resp := doRequest(req, err)

		assertStatus(t, 200, resp)
		assertBody(t, "password updated", resp)
	})
	t.Run("udate emailHandler", func(t *testing.T) {
		u := newTestUserService()
		//users := NewInMemoryUserStorage()

		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		ts := httptest.NewServer(http.HandlerFunc(u.Register))

		ts3 := httptest.NewServer(j.jwtAuth(u.repository, u.updateEmailHandler))

		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		params2 := map[string]interface{}{
			"email":         "testnew@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))

		Useruser, _ := u.repository.Get("test@mail.com")
		adminJwt, _ := j.GenearateJWT(Useruser)

		req, err := http.NewRequest(http.MethodGet, ts3.URL, prepareParams(t, params2))
		req.Header.Add("Authorization", "Bearer "+string(adminJwt))
		resp := doRequest(req, err)

		assertStatus(t, 200, resp)
		assertBody(t, "email updated", resp)
	})

	t.Run("validation password register", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "sixlit",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "Password at least 8 symbols", resp)
	})
	t.Run("validation email register", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "",
			"password":      "sixflitff",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "The email field is required!", resp)
	})
	t.Run("validation email ", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "213eurdf",
			"password":      "sixflitff",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "The email field should be a valid email address!", resp)
	})
	t.Run("validation cake register", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@gmail.com",
			"password":      "sixflitff",
			"favorite_cake": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "Favorite cake should not be empty", resp)
	})
	t.Run("validation cake alphabetic register", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@gmail.com",
			"password":      "sixflitff",
			"favorite_cake": "346234566345",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "Favorite cake should be only alphabetic", resp)
	})

	t.Run("jwt key by uncorrect passwd", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		ts2 := httptest.NewServer(http.HandlerFunc(u.Register))
		defer func() {
			ts.Close()
		}()

		user := User{
			Email:          "test@gmail.com",
			PasswordDigest: "newpassword",
			FavoriteCake:   "cheesecake",
		}
		u.repository.Add(user.Email, user)

		params := map[string]interface{}{
			"email":         "test@gmail.com",
			"password":      "newpassword",
			"favorite_cake": "cheesecake",
		}
		params2 := map[string]interface{}{
			"email":    "test@gmail.com",
			"password": "newpasswo",
		}
		doRequest(http.NewRequest(http.MethodPost, ts2.URL+"/user/register", prepareParams(t, params)))
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/jwt", prepareParams(t, params2)))
		//jwt, _ := j.GenearateJWT(user)
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

}
