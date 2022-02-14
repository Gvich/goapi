package main

import (
	"testing"
)

func TestUser_repository(t *testing.T) {
	t.Run("add user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		email := "test@gmail.com"
		user := User{
			Email:          email,
			PasswordDigest: "testtest",
			FavoriteCake:   "testtest",
		}
		ok := users.Add(email, user)
		ok2 := users.Add(email, user)
		if !(ok == nil && ok2 != nil) {
			t.Error("you have added the same user again ")
		}

	})
	t.Run("delete user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		email := "test@gmail.com"
		user := User{
			Email:          email,
			PasswordDigest: "testtest",
			FavoriteCake:   "testtest",
		}
		users.Add(email, user)
		users.Delete(email)
		_, ok := users.Delete(email)
		if ok == nil {
			t.Error("user doesn`t exist")
		}

	})
	t.Run("update user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		email := "test@gmail.com"
		user := User{
			Email:          email,
			PasswordDigest: "testtest",
			FavoriteCake:   "testtest",
		}
		user2 := User{
			Email:          email,
			PasswordDigest: "UPdateduser",
			FavoriteCake:   "UPdateduser",
		}
		user3 := User{
			Email:          "@gmail.com",
			PasswordDigest: "UPdateduser",
			FavoriteCake:   "UPdateduser",
		}

		users.Add(email, user)
		ok2 := users.Update(email, user2)
		if ok2 != nil {
			t.Error("you can`t update user by this email ")
		}
		ok2 = users.Update("gmail.com", user3)
	})
	t.Run("get user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		email := "test@gmail.com"
		user := User{
			Email:          email,
			PasswordDigest: "testtest",
			FavoriteCake:   "testtest",
		}
		users.Add(email, user)
		user2, ok := users.Get(email)
		if ok != nil {
			t.Error("user dosen`t exist")
		}
		if user2.FavoriteCake == "" && user2.PasswordDigest == "" {
			t.Error("users fields is empty")
		}

	})

}
