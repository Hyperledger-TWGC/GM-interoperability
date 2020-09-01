package main

import "testing"

func Fatal(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}
