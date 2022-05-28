package utils

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func CheckUserIsRoot() string {
	stdout, err := exec.Command("ps", "-o", "user=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return string(stdout)
}

func IsRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}
