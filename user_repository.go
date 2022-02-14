package main

import (
	"errors"
	//"fmt"
	"sync"
)

type InMemoryUserStorage struct {
	lock    sync.RWMutex
	storage map[string]User
}

func NewInMemoryUserStorage() *InMemoryUserStorage {
	return &InMemoryUserStorage{
		lock:    sync.RWMutex{},
		storage: make(map[string]User),
	}
}

func (repo *InMemoryUserStorage) Add(login string, userNew User) error {
	repo.lock.Lock()
	defer repo.lock.Unlock()

	_, ok := repo.storage[login]
	if ok {
		return errors.New("user with same login already exists")
	}

	repo.storage[login] = userNew

	return nil
}
func (repo *InMemoryUserStorage) Update(login string, userN User) error {
	repo.lock.Lock()
	defer repo.lock.Unlock()

	_, ok := repo.storage[login]
	if !ok {
		return errors.New(" there is no such user to update ")
	}
	repo.storage[login] = userN
	return nil
}

func (repo *InMemoryUserStorage) Get(login string) (User, error) {
	repo.lock.Lock()
	defer repo.lock.Unlock()
	getUser, ok := repo.storage[login]
	if !ok {
		return getUser, errors.New("invalid login params")
	}
	return getUser, nil
}

func (user *InMemoryUserStorage) Delete(key string) (User, error) {
	user.lock.Lock()
	defer user.lock.Unlock()

	name, ok := user.storage[key]
	if !ok {
		return name, errors.New("user does not exist")
	}

	delete(user.storage, key)
	return name, nil
}

// Add should return error if user with given key (login) is already present
// Update should return error if there is no such user to update
// Delete should return error if there is no such user to delete
// Delete should return deleted user
