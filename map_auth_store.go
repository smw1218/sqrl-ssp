package ssp

import (
	"fmt"
	"log"
	"sync"
)

// MapAuthStore stores identities in a map in the process.
// Great for testing but you should probably use some database
// to store these in a production environment.
type MapAuthStore struct {
	store *sync.Map
}

// NewMapAuthStore inits the internal map
func NewMapAuthStore() *MapAuthStore {
	return &MapAuthStore{&sync.Map{}}
}

// FindIdentity implements AuthStore
func (m *MapAuthStore) FindIdentity(idk string) (*SqrlIdentity, error) {
	if knownUser, ok := m.store.Load(idk); ok {
		log.Printf("Found existing identity: %#v", knownUser)
		if identity, ok := knownUser.(*SqrlIdentity); ok {
			return identity, nil
		}
		return nil, fmt.Errorf("Wrong type for identity %t", knownUser)
	}
	return nil, ErrNotFound
}

// SaveIdentity implements AuthStore
func (m *MapAuthStore) SaveIdentity(identity *SqrlIdentity) error {
	m.store.Store(identity.Idk, identity)
	return nil
}

// DeleteIdentity implements AuthStore
func (m *MapAuthStore) DeleteIdentity(idk string) error {
	m.store.Delete(idk)
	return nil
}
