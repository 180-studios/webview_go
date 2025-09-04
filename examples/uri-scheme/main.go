package main

import (
	"embed"
	"io/fs"

	webview "github.com/180-studios/webview_go"
)

//go:embed content
var content embed.FS

func main() {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Basic Example")
	w.SetSize(480, 320, webview.HintNone)

	serveFs, err := fs.Sub(content, "content")
	if err != nil {
		panic(err)
	}
	w.SetVirtualFileHosting("app.local", serveFs)

	w.Navigate("app.local://index.html")
	w.Run()
}
