package utils

import (
	"errors"
	"strings"

	"github.com/sirupsen/logrus"
)

func GetLogrusLogLevelFromString(input string) (level logrus.Level, err error) {
	input = strings.ToLower(input)
	if input == "debug" {
		return logrus.DebugLevel, nil
	} else if input == "info" {
		return logrus.InfoLevel, nil
	} else if input == "warning" {
		return logrus.WarnLevel, nil
	} else if input == "error" {
		return logrus.ErrorLevel, nil
	} else if input == "fatal" {
		return logrus.FatalLevel, nil
	}

	return logrus.Level(0), errors.New("log level is invalid")
}
