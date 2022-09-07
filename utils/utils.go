package utils

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

func Check(err error, msg string) {
	if err != nil {
		if msg != "" {
			log.Fatalf("%s -- %v", msg, err)
		} else {
			log.Fatal(err)
		}
	}
}

func Prompt(question string, sensitive bool) interface{} {
	var input interface{}
	fmt.Println(question)
	if sensitive {
		input, _ = terminal.ReadPassword(0)
	} else {
		input, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	return input
}
