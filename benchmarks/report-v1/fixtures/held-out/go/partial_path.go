package benchmark

import (
	"net/http"
	"os"
)

func download(response http.ResponseWriter, request *http.Request) {
	content, _ := os.ReadFile(resolveTenantPath(request.URL.Query().Get("path")))
	_, _ = response.Write(content)
}

func resolveTenantPath(requested string) string {
	return requested
}
