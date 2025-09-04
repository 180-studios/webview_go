package main

import webview "github.com/180-studios/webview_go"

func main() {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Basic Example")
	w.SetSize(480, 320, webview.HintNone)

	w.RegisterURIScheme("app.local", handleURIScheme)
	w.Navigate("app.local://index.html")

	w.Run()
}

func handleURIScheme(uri string, path string) (webview.URISchemeResponse, error) {
	return webview.URISchemeResponse{
		Status:      200,
		ContentType: "text/html",
		Data:        []byte("<h1>uri-scheme example</h1>" + "uri: " + uri + " path: " + path),
	}, nil
}
