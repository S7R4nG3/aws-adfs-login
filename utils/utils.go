package utils

import (
	"log"
)

// An open error checking function that can be used to return and error message
// and convenient sys.exit call.
func Check(err error, msg string) {
	if err != nil {
		if msg != "" {
			log.Fatalf("%s -- %v", msg, err)
		} else {
			log.Fatal(err)
		}
	}
}
