package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/armon/go-radix"
	"github.com/go-chi/chi/middleware"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
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
	storageView   sdklogical.Storage
	storagePrefix string
	l             sync.RWMutex
}

type Router struct {
	root               *radix.Tree // tree of mountPath -> routeEntry
	mountUUIDCache     *radix.Tree
	mountAccessorCache *radix.Tree // tree of mountAccesor -> mountEntry
	// storagePrefix maps the prefix used for storage (ala the BarrierView)
	// to the backend. This is used to map a key back into the backend that owns it.
	// For example, provider/uuid1/foobar -> providers/ (aws backend) + foobar
	storagePrefix *radix.Tree
	mu            sync.RWMutex

	logger *logger.GatedLogger
}

func NewRouter(logger *logger.GatedLogger) *Router {
	return &Router{
		root:               radix.New(),
		storagePrefix:      radix.New(),
		mountUUIDCache:     radix.New(),
		mountAccessorCache: radix.New(),
		logger:             logger,
	}
}

type ValidateMountResponse struct {
	MountType     string `json:"mount_type" mapstructure:"mount_type"`
	MountAccessor string `json:"mount_accessor" mapstructure:"mount_accessor"`
	MountPath     string `json:"mount_path" mapstructure:"mount_path"`
}

func (r *Router) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.root = radix.New()
	r.storagePrefix = radix.New()
	r.mountUUIDCache = radix.New()
	r.mountAccessorCache = radix.New()
}

// ValidateMountByAccessor returns the mount type and ID for a given mount
// accessor
func (r *Router) ValidateMountByAccessor(accessor string) *ValidateMountResponse {
	if accessor == "" {
		return nil
	}

	mountEntry := r.MatchingMountByAccessor(accessor)
	if mountEntry == nil {
		return nil
	}

	mountPath := mountEntry.Path
	if mountEntry.Class == mountClassAuth {
		mountPath = authRoutePrefix + mountPath
	}

	return &ValidateMountResponse{
		MountAccessor: mountEntry.Accessor,
		MountType:     mountEntry.Type,
		MountPath:     mountPath,
	}
}

// SaltID is used to apply a salt and hash to an ID to make sure its not reversible
func (re *routeEntry) SaltID(id string) string {
	return salt.SaltID(re.mountEntry.UUID, id, salt.SHA1Hash)
}

// Mount is used to expose a logical backend at a given prefix, using a unique salt,
// and the barrier view for that path.
func (r *Router) Mount(prefix string, backend logical.Backend, mountEntry *MountEntry, storageView BarrierView) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// prepend namespace
	prefix = mountEntry.Namespace().Path + prefix

	// Check if this is a nested mount
	if existing, _, ok := r.root.LongestPrefix(prefix); ok && existing != "" {
		return fmt.Errorf("cannot mount under existing mount %q", existing)
	}

	// Create a mount entry
	re := &routeEntry{
		tainted:       mountEntry.Tainted,
		backend:       backend,
		mountEntry:    mountEntry,
		storagePrefix: storageView.Prefix(),
		storageView:   storageView,
	}

	switch {
	case prefix == "":
		return fmt.Errorf("missing prefix to be used for router entry; mount_path: %q, mount_type: %q", re.mountEntry.Path, re.mountEntry.Class)
	case re.storagePrefix == "":
		return fmt.Errorf("missing storage view prefix; mount_path: %q, mount_type: %q", re.mountEntry.Path, re.mountEntry.Class)
	case re.mountEntry.UUID == "":
		return fmt.Errorf("missing mount identifier; mount_path: %q, mount_type: %q", re.mountEntry.Path, re.mountEntry.Class)
	case re.mountEntry.Accessor == "":
		return fmt.Errorf("missing mount accessor; mount_path: %q, mount_type: %q", re.mountEntry.Path, re.mountEntry.Class)
	}

	r.root.Insert(prefix, re)
	r.storagePrefix.Insert(re.storagePrefix, re)
	r.mountUUIDCache.Insert(re.mountEntry.UUID, re.mountEntry)
	r.mountAccessorCache.Insert(re.mountEntry.Accessor, re.mountEntry)

	r.logger.Info("backend mounted", logger.String("mount_path", prefix))

	return nil
}

// Unmount is used to remove a logical backend from a given prefix
func (r *Router) Unmount(ctx context.Context, prefix string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	prefix = ns.Path + prefix

	r.mu.Lock()
	defer r.mu.Unlock()

	// Fast-path out if the backend doesn't exist
	raw, ok := r.root.Get(prefix)
	if !ok {
		return nil
	}

	// Call backend's Cleanup routine
	re := raw.(*routeEntry)
	re.l.Lock()
	defer re.l.Unlock()
	if re.backend != nil {
		re.backend.Cleanup(ctx)
	}

	// Purge from the radix trees
	r.root.Delete(prefix)
	r.storagePrefix.Delete(re.storagePrefix)
	r.mountUUIDCache.Delete(re.mountEntry.UUID)
	r.mountAccessorCache.Delete(re.mountEntry.Accessor)

	r.logger.Info("backend unmounted", logger.String("mount_path", prefix))

	return nil
}

// MatchingMountByAccessor returns the backend by accessor lookup
func (r *Router) MatchingMountByAccessor(mountAccessor string) *MountEntry {
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
	if prefixMatch := r.matchingPrefixInternal(ctx, path); prefixMatch != "" {
		return prefixMatch
	}
	if nsMatch := r.matchingNamespaceInternal(ctx, path); nsMatch != "" {
		return nsMatch
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
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ""
	}
	path = ns.Path + path

	mount, _, ok := r.root.LongestPrefix(path)
	if !ok {
		return ""
	}
	return mount
}

// matchingPrefixInternal returns a mount prefix that a path may be a part of
func (r *Router) matchingPrefixInternal(ctx context.Context, path string) string {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ""
	}
	path = ns.Path + path

	var existing string
	fn := func(existingPath string, v interface{}) bool {
		if strings.HasPrefix(existingPath, path) {
			existing = existingPath
			return true
		}
		return false
	}
	r.root.WalkPrefix(path, fn)
	return existing
}

// matchingNamespaceInternal returns a namespace prefix that a path may be a part of
func (r *Router) matchingNamespaceInternal(ctx context.Context, path string) string {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return ""
	}
	// Ensure comparisons are done against absolute paths within the
	// current namespace context, consistent with other matching helpers.
	// Without this, a mount path that matches the current namespace name
	// (e.g., mounting "team14/" inside namespace "team14/") would be
	// incorrectly detected as conflicting with the namespace itself.
	path = ns.Path + path

	// Every namespace has a sys/ mount. We can use that as a sentinel that
	// our given path conflicts. Walk the parent namespace of path and check
	// if there's a common prefix between a child namespace's sys/ entry and
	// path.
	//
	// This allows us to avoid calling into the namespace store, which may be
	// locked as we're trying to mount required mounts for a new namespace.
	var existing string
	fn := func(existingPath string, v interface{}) bool {
		nsPath, ok := strings.CutSuffix(existingPath, "sys/")
		if !ok {
			return false
		}

		// Ignore the current namespace's own sys mount; we only want to
		// detect conflicts with child namespace prefixes.
		if nsPath == ns.Path {
			return false
		}

		if strings.HasPrefix(path, nsPath) {
			existing = nsPath
			return true
		}

		return false
	}

	r.root.WalkPrefix(ns.Path, fn)
	return existing
}

// Taint is used to mark a path as tainted.
// A tainted path is not resolvable.
func (r *Router) Taint(ctx context.Context, path string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	path = ns.Path + path

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
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	path = ns.Path + path

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

func (r *Router) MatchingMountByUUID(mountID string) *MountEntry {
	if mountID == "" {
		return nil
	}

	r.mu.RLock()

	_, raw, ok := r.mountUUIDCache.LongestPrefix(mountID)
	if !ok {
		r.mu.RUnlock()
		return nil
	}

	r.mu.RUnlock()
	return raw.(*MountEntry)
}

// MatchingStorageByAPIPath/StoragePath returns the storage used for
// API/Storage paths respectively
func (r *Router) MatchingStorageByAPIPath(ctx context.Context, path string) sdklogical.Storage {
	return r.matchingStorage(ctx, path, true)
}

func (r *Router) MatchingStorageByStoragePath(ctx context.Context, path string) sdklogical.Storage {
	return r.matchingStorage(ctx, path, false)
}

func (r *Router) matchingStorage(ctx context.Context, path string, apiPath bool) sdklogical.Storage {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil
	}
	path = ns.Path + path

	var raw interface{}
	var ok bool
	r.mu.RLock()
	if apiPath {
		_, raw, ok = r.root.LongestPrefix(path)
	} else {
		_, raw, ok = r.storagePrefix.LongestPrefix(path)
	}
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	return raw.(*routeEntry).storageView
}

// MatchingMountEntry returns the MountEntry used for a path
func (r *Router) MatchingMountEntry(ctx context.Context, path string) *MountEntry {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil
	}
	path = ns.Path + path

	r.mu.RLock()
	_, raw, ok := r.root.LongestPrefix(path)
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	return raw.(*routeEntry).mountEntry
}

// MatchingBackend returns the backend used for a path
func (r *Router) MatchingBackend(ctx context.Context, path string) logical.Backend {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil
	}
	path = ns.Path + path

	r.mu.RLock()
	// Find the longest prefix match in the radix tree
	_, raw, found := r.root.LongestPrefix(path)
	r.mu.RUnlock()
	if !found {
		r.logger.Error("no route found for the provided path",
			logger.String("path", path),
		)
		return nil
	}

	re := raw.(*routeEntry)
	re.l.RLock()
	defer re.l.RUnlock()

	return re.backend
}

func (r *Router) MatchingMountByAPIPath(ctx context.Context, path string) string {
	re, _ := r.matchingRouteEntryByPath(ctx, path, true)
	if re == nil {
		return ""
	}

	re.l.RLock()
	defer re.l.RUnlock()

	return re.mountEntry.Path
}

func (r *Router) matchingRouteEntryByPath(ctx context.Context, path string, apiPath bool) (*routeEntry, bool) {
	var raw interface{}
	var ok bool
	r.mu.RLock()
	if apiPath {
		_, raw, ok = r.root.LongestPrefix(path)
	} else {
		_, raw, ok = r.storagePrefix.LongestPrefix(path)
	}
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}

	// Extract the mount path and storage prefix
	re := raw.(*routeEntry)
	return re, true
}

// MatchingStoragePrefixByAPIPath the storage prefix for the given api path
func (r *Router) MatchingStoragePrefixByAPIPath(ctx context.Context, path string) (string, bool) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", false
	}
	path = ns.Path + path

	re, found := r.matchingRouteEntryByPath(ctx, path, true)
	if !found {
		return "", false
	}

	re.l.RLock()
	defer re.l.RUnlock()

	return re.storagePrefix, true
}

// MatchingAPIPrefixByStoragePath the api path information for the given storage path
func (r *Router) MatchingAPIPrefixByStoragePath(ctx context.Context, path string) (*namespace.Namespace, string, string, bool) {
	re, found := r.matchingRouteEntryByPath(ctx, path, false)
	if !found {
		return nil, "", "", found
	}

	re.l.RLock()
	defer re.l.RUnlock()

	mountPath := re.mountEntry.Path
	// Add back the prefix for auth backends
	if strings.HasPrefix(path, authBarrierPrefix) {
		mountPath = authBarrierPrefix + mountPath
	}

	return re.mountEntry.Namespace(), mountPath, re.storagePrefix, found
}

// Route is used to route a given request
func (r *Router) Route(w http.ResponseWriter, req *http.Request) {
	ns, err := namespace.FromContext(req.Context())
	if err != nil {
		r.logger.Error("Fail to extract namespace from the request context", logger.Err(err))
		http.Error(w, "Fail to extract namespace from the request context", http.StatusBadRequest)
		return
	}

	requestPath := req.URL.Path
	originalPath := req.Context().Value(logical.OriginalPath).(string)

	r.mu.RLock()
	mount, raw, ok := r.root.LongestPrefix(ns.Path + requestPath)
	if !ok && !strings.HasSuffix(requestPath, "/") {
		// Re-check for a backend by appending a slash. This lets "foo" mean
		// "foo/" at the root level which is almost always what we want.
		requestPath += "/"
		mount, raw, ok = r.root.LongestPrefix(ns.Path + requestPath)
	}
	r.mu.RUnlock()

	if !ok {
		r.logger.Error("no route found",
			logger.Err(fmt.Errorf("no handler for route %q. route entry not found", originalPath)),
			logger.String("namespace", ns.Path),
			logger.String("url", req.URL.String()),
			logger.String("method", req.Method),
			logger.String("request_id", middleware.GetReqID(req.Context())),
		)
		http.Error(w, "no route found for the provided path", http.StatusNotFound)
		return
	}
	re := raw.(*routeEntry)

	re.l.RLock()
	defer re.l.RUnlock()

	// Filtered mounts will have a nil backend
	if re.backend == nil {
		r.logger.Error("no route found",
			logger.Err(fmt.Errorf("no handler for route %q. route entry found, but backend is nil", originalPath)),
			logger.String("namespace", ns.Path),
			logger.String("url", req.URL.String()),
			logger.String("method", req.Method),
			logger.String("request_id", middleware.GetReqID(req.Context())),
		)
		http.Error(w, "no route found for the provided path", http.StatusNotFound)
		return
	}

	// If the path or namespace is tainted, we reject any operation
	if re.tainted || ns.Tainted {
		r.logger.Error("no route found",
			logger.Err(fmt.Errorf("no handler for route %q. entry or namespace is tainted", req.URL.Path)),
			logger.String("namespace", ns.Path),
			logger.String("url", req.URL.String()),
			logger.String("method", req.Method),
			logger.String("request_id", middleware.GetReqID(req.Context())),
		)
		http.Error(w, "no route found for the provided path", http.StatusNotFound)
		return
	}

	// Adjust the path to exclude the routing prefix
	// The mount path includes the namespace prefix, so we need to trim using the full path
	// ns1/ + sys/namespaces/test - ns1/sys/ = namepaces/test
	relativePath := strings.TrimPrefix(ns.Path+requestPath, mount)

	// Ensure the path has a leading slash for the backend router
	if !strings.HasPrefix(relativePath, "/") {
		relativePath = "/" + relativePath
	}

	// Set the request path to the path relative to the mount
	req.URL.Path = relativePath
	req.URL.RawPath = ""

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
