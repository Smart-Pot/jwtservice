package jwtservice

import (
	"testing"
)

func TestResolve(t *testing.T) {
	n := "Ahmet"
	s := &JwtService{}
	tokenStr, err := s.Tokenize(n)
	if err != nil {
		t.Error("Err", err)
		t.FailNow()
	}
	claims, err := s.Verify(tokenStr)
	if err != nil {
		t.Error("Err", err)
		t.FailNow()
	}
	if claims["userId"] != n {
		t.Error("Mismatch claim.UserID", claims["userId"], "n", n)
		t.FailNow()
	}
}

func TestGetUserID(t *testing.T) {
	n := "Ahmet"
	s := &JwtService{}
	tokenStr, err := s.Tokenize(n)
	if err != nil {
		t.Error("Err", err)
		t.FailNow()
	}
	id, err := s.GetUserID(tokenStr)
	if err != nil {
		t.Error("Err", err)
		t.FailNow()
	}
	if id != n {
		t.Error("ERR! id", id, "n", n)
		t.FailNow()
	}
}
