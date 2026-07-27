package benchmark

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func download(response http.ResponseWriter, request *http.Request) {
	root := "/srv/public"
	requested := filepath.Clean(filepath.Join(root, request.URL.Query().Get("path")))
	if !strings.HasPrefix(requested, root+string(os.PathSeparator)) {
		http.Error(response, "blocked", http.StatusBadRequest)
		return
	}
	content, _ := os.ReadFile(requested)
	_, _ = response.Write(content)
}
