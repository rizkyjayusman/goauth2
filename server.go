package main

import (
	"fmt"

	"com.rizkyjayusmangoauth2/cmd"
	"github.com/labstack/gommon/color"
)

func main() {
	cmd, err := cmd.New(cmd.Config{})
	if err != nil {
		msg := fmt.Sprintf("setup failure: %s", err.Error())
		fmt.Println(color.Red(msg))
		return
	}

	cmd.Execute()
}
