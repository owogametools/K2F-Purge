package main

import (
	"log"
	"os"
	"os/user"
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/owogametools/k2f-purge/appui"
	"github.com/owogametools/k2f-purge/internal/elev"
	"github.com/owogametools/k2f-purge/internal/service"

	// Registers the app's message catalogs with the UI's i18n package.
	_ "github.com/owogametools/k2f-purge/locales"
)

// version is stamped by release builds with -X main.version=<tag>.
var version = ""

func main() {
	// An elevated child runs one privileged operation and exits.
	if handled, code := elev.RunOpFromArgs(os.Args[1:]); handled {
		os.Exit(code)
	}
	// Windows relaunches itself with UAC; the original process exits.
	if relaunched, err := elev.EnsureElevated(os.Args[1:]); err != nil {
		log.Printf("elevation: %v", err)
	} else if relaunched {
		return
	}

	name := mygo.App.Name()
	if name == "" {
		name = "K2F PURGE"
	}
	appVersion := version
	if appVersion == "" {
		appVersion = mygo.App.Version()
	}
	if appVersion == "" {
		appVersion = "0.1.0"
	}
	username := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	svc, err := service.New(name, appVersion, runtime.GOOS, runtime.GOARCH, username)
	if err != nil {
		log.Fatal(err)
	}
	a := appui.New(svc.Info(), svc)

	mygo.App.WhenReady(func() {
		w := mygo.NewWindow(mygo.WindowOptions{
			Title:             "K2F PURGE",
			Width:             1340,
			Height:            860,
			MinWidth:          1100,
			MinHeight:         720,
			StateKey:          "main",
			Frameless:         true,
			TitleBarStyle:     mygo.TitleBarHidden,
			HideWindowButtons: true,
			BackgroundColor:   "#050505",
			Content:           ui.View(a.View),
		})
		a.Attach(w)
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
