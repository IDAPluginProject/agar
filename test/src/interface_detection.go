package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
)

func ExampleScanner_lines() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Println(scanner.Text()) // Println will add back the final '\n'
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}

func main() {
	fmt.Println("Please enter some text (Ctrl+D to end):")

	m := make(map[string]any)

	m["key"] = rand.Int()

	fmt.Println("Map:", m)

	ExampleScanner_lines()
}
