package main

import "fmt"

type A struct {
	a int
}

func (a A) String() string {
	return "A" + string(a.a)
}

type Stringer interface {
	String() string
}

func Print(s Stringer) {
	fmt.Println(s.String())
}

func main() {
	a := A{a: 10}
	Print(a)
}
