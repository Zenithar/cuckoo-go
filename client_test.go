package cuckoo_test

import (
	"testing"

	"github.com/davecgh/go-spew/spew"

	"zenithar.org/go/cuckoo-go"
)

func TestFileCreate(t *testing.T) {
	client := cuckoo.NewClientWithBasicAuthentication("https://localhost/api", "user", "password")

	res, err := client.FileCreate("pafish.exe")
	if err != nil {
		spew.Dump(err)
		t.Fail()
	}

	spew.Dump(res)
}
