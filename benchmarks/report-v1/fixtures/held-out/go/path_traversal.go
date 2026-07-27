package benchmark

import (
	"net/http"
	"os"
)

func download(response http.ResponseWriter, request *http.Request) {
	content, _ := os.ReadFile(request.URL.Query().Get("path"))
	_, _ = response.Write(content)
}
