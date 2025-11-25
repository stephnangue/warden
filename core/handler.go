package core

import "net/http"

// ServeHTTP makes the Core an http.Handler
func (c *Core) ServeHTTP (w http.ResponseWriter, req *http.Request) {
	ok := c.auditRequest(req)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
	}

	c.router.Route(w, req)
}