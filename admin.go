package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"time"
)

type UserBanParams struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}
type BanHistoryList struct {
	Executor string
	IsBan    bool
	Time     time.Time
	Reason   string
}
type EmailParams = struct {
	Email string `json:"email"`
}
type History []BanHistoryList
type UserUnbanParams = EmailParams

func banUserHandler(w http.ResponseWriter, r *http.Request, executor User, users UserRepository) {
	params := &UserBanParams{}
	err := json.NewDecoder(r.Body).Decode(params)

	if _, err := mail.ParseAddress(params.Email); err != nil {
		handleError(err, w)
		return
	}
	user, getErr := users.Get(params.Email)
	if getErr != nil {
		handleError(getErr, w)
		return
	} /*
		if executor.Role == "UserRole" {
			if user.Role == "AdminRole" {
				handleError(errors.New("permission denied"), w)
				return
			}
		}*/

	banHistoryList := BanHistoryList{
		Executor: user.Email,
		IsBan:    true,
		Time:     time.Now(),
		Reason:   params.Reason,
	}
	user.Ban = true
	user.BanHistory = append(user.BanHistory, banHistoryList)

	err = users.Update(user.Email, user)
	if err != nil {
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user " + user.Email + " banned"))
}

func unbanUserHandler(w http.ResponseWriter, r *http.Request, executor User, users UserRepository) {
	params := &UserUnbanParams{}
	err := json.NewDecoder(r.Body).Decode(params)

	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if _, err := mail.ParseAddress(params.Email); err != nil {
		handleError(err, w)
		return
	}
	user, getErr := users.Get(params.Email)
	if getErr != nil {
		handleError(getErr, w)
		return
	}
	if executor.Role == "UserRole" {
		if user.Role == "AdminRole" {
			handleError(errors.New("permission denied"), w)
			return
		}
	}

	banHistoryList := BanHistoryList{
		Executor: executor.Email,
		IsBan:    false,
		Time:     time.Now(),
		Reason:   "",
	}
	user.Ban = false
	user.BanHistory = append(user.BanHistory, banHistoryList)

	err = users.Update(user.Email, user)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user " + user.Email + " unbanned"))
}

func inspectHandler(w http.ResponseWriter, r *http.Request, _ User, users UserRepository) {
	email := r.URL.Query().Get("email")
	user, getErr := users.Get(email)
	if getErr != nil {
		handleError(getErr, w)
		return
	}
	HistoryStr := ""

	for _, query := range user.BanHistory {
		banStr := ""
		if query.IsBan {
			banStr = "banned (reason: " + query.Reason + ")"
		} else {
			banStr = "unbanned"
		}
		HistoryStr += "-- was " + banStr + " at " +
			query.Time.Format("30 October 2021 23:00:00") +
			" by " + query.Executor + "\n"
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user " + user.Email + ":\n" + HistoryStr))
}
