package main

import (
	"crypto/sha1"
	"fmt"
	"math/rand"
)

func main() {
	hash := sha1.New()
	hash.Write([]byte("Hello, World!"))
	h := hash.Sum(nil)
	rng := rand.New(rand.NewSource(int64(h[0])))
	for i := 0; i < 10; i++ {
		fmt.Println(rng.Intn(6) + 1) // Print random numbers between 1 and 6
		fmt.Println(rng.Int63())
	}
}
