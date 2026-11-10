package main

import (
	"crypto/sha256"
	"hash"
)

func newHash() hash.Hash { return sha256.New() }
