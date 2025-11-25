package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/armon/go-radix"
	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

type contextKey string

const (
    OriginalPath contextKey = "originalPath"
)

// routeEntry is used to represent a mount point in the router
type routeEntry struct {
	tainted       bool
	backend       logical.Backend
	mountEntry    *MountEntry
	l             sync.RWMutex
}

type Router struct {
	root               *radix.Tree // tree of mountPath -> routeEntry
	mountAccessorCache *radix.Tree // tree of mountAccesor -> mountEntry
	mu                 sync.RWMutex

	logger           logger.Logger
}

func NewRouter(logger logger.Logger) *Router {
	return &Router{
		root:                   radix.New(),
		mountAccessorCache:     radix.New(),
		logger:                 logger,
	}
}

func (r *Router) Mount(mountPath string, backend logical.Backend, mountEntry *MountEntry) error {
	r.mu.RLock()
	existing, exists := r.root.Get(mountPath); 
	r.mu.RUnlock()

	if exists && existing != nil {
		return fmt.Errorf("path %s is already mounted", mountPath)
	}

	// Create a mount entry
	re := &routeEntry{
		backend:       backend,
		mountEntry:    mountEntry,
	}

	r.root.Insert(mountPath, re)
	r.mountAccessorCache.Insert(re.backend.GetAccessor(), re.mountEntry)

	r.logger.Info("backend mounted", logger.String("mount_path", mountPath))

	return nil
}

func (r *Router) Unmount(mountPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Fast-path out if the backend doesn't exist
	raw, ok := r.root.Get(mountPath)
	if !ok {
		return nil
	}

	// Call backend's Cleanup routine
	re := raw.(*routeEntry)
	re.l.Lock()
	defer re.l.Unlock()
	if re.backend != nil {
		re.backend.Cleanup()
	}

	// Purge from the radix trees
	r.root.Delete(mountPath)
	r.mountAccessorCache.Delete(re.backend.GetAccessor())

	r.logger.Info("backend unmounted", logger.String("mount_path", mountPath))
	
	return nil
}

// MatchingBackend returns the backend used for a path
func (r *Router) MatchingBackend(ctx context.Context, mountPath string) logical.Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Find the longest prefix match in the radix tree
	_, raw, found := r.root.LongestPrefix(mountPath)
	if !found {
		r.logger.Error("no route found for the provided path", 
			logger.String("path", mountPath),
		)
		return nil
	}

	re := raw.(*routeEntry)
	re.l.RLock()
	defer re.l.RUnlock()

	return re.backend
} 

// MatchingMountByAccessor returns the backend by accessor lookup
func (r *Router) MatchingMountByAccessor(mountAccessor string) *MountEntry  {
	if mountAccessor == "" {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	_, raw, ok := r.mountAccessorCache.LongestPrefix(mountAccessor)
	if !ok {
		return nil
	}

	return raw.(*MountEntry)
}

// MountConflict determines if there are potential path conflicts
func (r *Router) MountConflict(ctx context.Context, path string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if exactMatch := r.matchingMountInternal(ctx, path); exactMatch != "" {
		return exactMatch
	}
	return ""
}

// MatchingMount returns the mount prefix that would be used for a path
func (r *Router) MatchingMount(ctx context.Context, path string) string {
	r.mu.RLock()
	mount := r.matchingMountInternal(ctx, path)
	r.mu.RUnlock()
	return mount
}

func (r *Router) matchingMountInternal(ctx context.Context, path string) string {
	mount, _, ok := r.root.LongestPrefix(path)
	if !ok {
		return ""
	}
	return mount
}

// Taint is used to mark a path as tainted.
// A tainted path is not resolvable.
func (r *Router) Taint(ctx context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, raw, ok := r.root.LongestPrefix(path)
	if ok {
		re := raw.(*routeEntry)
		re.l.Lock()
		re.tainted = true
		re.l.Unlock()
	}
	return nil
}

// Untaint is used to unmark a path as tainted.
func (r *Router) Untaint(ctx context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, raw, ok := r.root.LongestPrefix(path)
	if ok {
		re := raw.(*routeEntry)
		re.l.Lock()
		re.tainted = false
		re.l.Unlock()
	}
	return nil
}

// Route is used to route a given request
func (r *Router) Route(w http.ResponseWriter, req *http.Request) {
	requestPath := strings.TrimPrefix(req.URL.Path, "/v1/")
	requestPath = strings.TrimPrefix(requestPath, "auth/")
	requestPath = strings.TrimSuffix(requestPath, "/")

	r.mu.RLock()
	mount, raw, ok := r.root.LongestPrefix(requestPath)
	if !ok && !strings.HasSuffix(requestPath, "/") {
		// Re-check for a backend by appending a slash. This lets "foo" mean
		// "foo/" at the root level which is almost always what we want.
		requestPath += "/"
		mount, raw, ok = r.root.LongestPrefix(requestPath)
	}
	r.mu.RUnlock()
	if !ok {
		r.logger.Error("no route found", 
			logger.Err(fmt.Errorf("no handler for route %q. route entry not found", req.URL.Path)),
			logger.String("url", req.URL.String()),
			logger.String("method", req.Method),
			logger.String("request_id", middleware.GetReqID(req.Context())),
		)
		http.Error(w, "no route found for the provided path", http.StatusNotFound)
		return
	}
	re := raw.(*routeEntry)

	// Filtered mounts will have a nil backend
	if re.backend == nil {
		r.logger.Error("no route found", 
			logger.Err(fmt.Errorf("no handler for route %q. route entry found, but backend is nil", req.URL.Path)),
			logger.String("url", req.URL.String()),
			logger.String("method", req.Method),
			logger.String("request_id", middleware.GetReqID(req.Context())),
		)
		http.Error(w, "no route found for the provided path", http.StatusNotFound)
		return 
	}

	// If the path or namespace is tainted, we reject any operation
	if re.tainted {
		r.logger.Error("no route found", 
			logger.Err(fmt.Errorf("no handler for route %q. route entry is tainted", req.URL.Path)),
			logger.String("url", req.URL.String()),
			logger.String("method", req.Method),
			logger.String("request_id", middleware.GetReqID(req.Context())),
		)
		http.Error(w, "no route found for the provided path", http.StatusNotFound)
		return 
	}

	mount = strings.TrimSuffix(mount, "/")
	relativePath := strings.TrimPrefix(strings.TrimSuffix(requestPath, "/"), mount)
	relativePath = strings.TrimPrefix(relativePath, "/")

	// Save original path
	originalPath := req.URL.Path

	req.URL.Path = "/" + relativePath
	// CRITICAL : Clear RawPath and let Go rebuild it if needed
	req.URL.RawPath = ""

	ctx := req.Context()
	ctx = context.WithValue(ctx, logical.OriginalPath, originalPath)
	req = req.WithContext(ctx)

	if err := re.backend.HandleRequest(w, req); err != nil {
		r.logger.Error("fail to handle request", 
			logger.String("url", req.URL.String()),
			logger.String("method", req.Method),
			logger.String("original_path", originalPath),
			logger.String("request_id", middleware.GetReqID(req.Context())),
		)

		// backend already wrote the error response
		return
	}
}

