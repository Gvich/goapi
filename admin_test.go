package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"testing"
)

func TestAdmin_JWT(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("deny acess be wrong login", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))

		ts3 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, banUserHandler))
		defer ts.Close()

		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "testtest",
			"favorite_cake": "cheesecake",
		}

		banParams := map[string]interface{}{
			"email":  "test@gmail.com",
			"reason": "testtest",
		}
		u.addAdmin()
		Adminuser, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		adminJwt, _ := jwtService.GenearateJWT(Adminuser)

		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		req, _ := http.NewRequest(http.MethodPost, ts3.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+adminJwt)
		resp := doRequest(req, nil)
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("banning user", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		ts3 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, banUserHandler))
		defer ts.Close()
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepassss",
			"favorite_cake": "cheesecake",
		}
		banParams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "making mess",
		}

		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		u.addAdmin()
		Adminuser, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		adminJwt, _ := jwtService.GenearateJWT(Adminuser)

		req, _ := http.NewRequest(http.MethodPost, ts3.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+string(adminJwt))
		resp := doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "user test@mail.com banned", resp)

	})

	t.Run("unbanning user", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		ts2 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, banUserHandler))
		ts3 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, unbanUserHandler))
		defer ts.Close()

		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		unbanParams := map[string]interface{}{
			"email": "test@mail.com",
		}
		banParams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "making mess",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		u.addAdmin()
		Adminuser, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		adminJwt, _ := jwtService.GenearateJWT(Adminuser)

		banReq, _ := http.NewRequest(http.MethodPost, ts2.URL+"/admin/ban", prepareParams(t, banParams))
		banReq.Header.Set("Authorization", "Bearer "+string(adminJwt))
		doRequest(banReq, nil)

		unbanReq, _ := http.NewRequest(http.MethodPost, ts3.URL+"/admin/unban", prepareParams(t, unbanParams))
		unbanReq.Header.Set("Authorization", "Bearer "+string(adminJwt))
		unbunned := doRequest(unbanReq, nil)

		assertStatus(t, 200, unbunned)
		assertBody(t, "user test@mail.com unbanned", unbunned)
	})

	t.Run("inspecting user with ban history", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		ts2 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, banUserHandler))
		ts3 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, unbanUserHandler))
		ts4 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, inspectHandler))

		defer ts.Close()

		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		jwtParams := map[string]interface{}{
			"email":    os.Getenv("CAKE_SUPERADMIN_EMAIL"),
			"password": os.Getenv("CAKE_SUPERADMIN_PASSWORD"),
		}
		banParams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "making mess",
		}

		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		u.addAdmin()
		Adminuser, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		adminJwt, _ := jwtService.GenearateJWT(Adminuser)

		banReq, _ := http.NewRequest(http.MethodPost, ts2.URL+"/admin/ban", prepareParams(t, banParams))
		banReq.Header.Set("Authorization", "Bearer "+string(adminJwt))
		banTime := time.Now().Format("30 October 2021 23:00:00")
		doRequest(banReq, nil)
		banStr := "-- was banned (reason: making mess) at " + banTime + " by test@mail.com" + "\n"

		unbanParams := map[string]interface{}{
			"email": "test@mail.com",
		}
		unbanReq, _ := http.NewRequest(http.MethodPost, ts3.URL+"/admin/unban", prepareParams(t, unbanParams))
		unbanReq.Header.Set("Authorization", "Bearer "+string(adminJwt))
		unbanTime := time.Now().Format("30 October 2021 23:00:00")
		doRequest(unbanReq, nil)
		unbanStr := "-- was unbanned at " + unbanTime + " by " +
			os.Getenv("CAKE_ADMIN_EMAIL") + "\n"

		inspectReq, _ := http.NewRequest(http.MethodGet,
			ts4.URL+"/admin/inspect?email=test@mail.com",
			prepareParams(t, jwtParams))
		inspectReq.Header.Set("Authorization", "Bearer "+string(adminJwt))
		inspectRest := doRequest(inspectReq, nil)

		assertStatus(t, 200, inspectRest)
		assertBody(t, "user test@mail.com:\n"+(banStr)+unbanStr, inspectRest)
	})

	t.Run("banned user accessing api with jwt", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		ts2 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, banUserHandler))
		ts3 := httptest.NewServer(jwtService.jwtAuth(u.repository, getCakeHandler))

		defer ts.Close()
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		banParams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "making mess",
		}

		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))

		u.addAdmin()
		Adminuser, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		adminJwt, _ := jwtService.GenearateJWT(Adminuser)

		Useruser, _ := u.repository.Get("test@mail.com")
		userJwt, _ := jwtService.GenearateJWT(Useruser)

		req, _ := http.NewRequest(http.MethodPost, ts2.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+string(adminJwt))
		resp := doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "user test@mail.com banned", resp)

		req, err := http.NewRequest(http.MethodGet, ts3.URL, nil)
		req.Header.Add("Authorization", "Bearer "+string(userJwt))
		bannedResp := doRequest(req, err)
		assertStatus(t, 401, bannedResp)
		assertBody(t, "you are banned! Reason: making mess", bannedResp)
	})

	t.Run("banning user with wrong email without @", func(t *testing.T) {
		u := newTestUserService()

		jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
		if jwtErr != nil {
			panic(jwtErr)
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		ts2 := httptest.NewServer(jwtService.jwtAuthAdmin(u.repository, banUserHandler))
		defer ts.Close()

		// registration
		registerParams := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts.URL+"/user/register", prepareParams(t, registerParams)))
		u.addAdmin()
		Adminuser, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		adminJwt, _ := jwtService.GenearateJWT(Adminuser)

		banParams := map[string]interface{}{
			"email":  "notAnEmail",
			"reason": "making mess",
		}
		req, _ := http.NewRequest(http.MethodPost, ts2.URL+"/admin/ban", prepareParams(t, banParams))
		req.Header.Set("Authorization", "Bearer "+string(adminJwt))
		resp := doRequest(req, nil)

		assertStatus(t, 422, resp)
		assertBody(t, "mail: missing '@' or angle-addr", resp)
	})

}
