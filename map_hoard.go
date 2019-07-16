package ssp

import (
	"fmt"
	"sync"
	"time"
)

type valExpire struct {
	value      interface{}
	expiration time.Time
}

func (ve valExpire) Expired() bool {
	return ve.expiration.Before(time.Now())
}

type MapHoard struct {
	cache map[Nut]*valExpire
	mutex *sync.Mutex
}

func NewMapHoard() *MapHoard {
	mh := &MapHoard{
		cache: make(map[Nut]*valExpire),
		mutex: &sync.Mutex{},
	}
	go mh.cleaner()
	return mh
}

func (mh *MapHoard) cleaner() {
	ticker := time.NewTicker(100 * time.Millisecond)
	for start := range ticker.C {
		mh.mutex.Lock()
		i := 0
		for k, v := range mh.cache {
			if v.Expired() {
				delete(mh.cache, k)
			}
			i++
			// check for going over time
			if i%100 == 0 {
				if time.Now().Sub(start) > 50*time.Millisecond {
					break
				}
			}
		}
		mh.mutex.Unlock()
	}
}

func (mh *MapHoard) Get(nut Nut) (interface{}, error) {
	mh.mutex.Lock()
	defer mh.mutex.Unlock()
	if value, ok := mh.cache[nut]; ok {
		if !value.Expired() {
			return value.value, nil
		} else {
			delete(mh.cache, nut)
		}
	}
	return nil, NotFoundError
}

func (mh *MapHoard) GetAndDelete(nut Nut) (interface{}, error) {
	mh.mutex.Lock()
	defer mh.mutex.Unlock()
	if value, ok := mh.cache[nut]; ok {
		delete(mh.cache, nut)
		if !value.Expired() {
			return value.value, nil
		}
	}
	return nil, NotFoundError
}

func (mh *MapHoard) Save(nut Nut, value interface{}, expiration time.Duration) error {
	if nut == "" {
		return fmt.Errorf("empty nuts are not allowed")
	}
	mh.mutex.Lock()
	defer mh.mutex.Unlock()
	mh.cache[nut] = &valExpire{
		value:      value,
		expiration: time.Now().Add(expiration),
	}
	return nil
}
