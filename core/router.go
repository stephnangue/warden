package core

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/armon/go-radix"
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

// matches when '+' is next to a non-slash char
var wcAdjacentNonSlashRegEx = regexp.MustCompile(`\+[^/]|[^/]\+`).MatchString

// routeEntry is used to represent a mount point in the router
type routeEntry struct {
	tainted        bool
	backend        logical.Backend
	mountEntry     *MountEntry
	storageView    sdklogical.Storage
	storagePrefix  string
	rootPaths      atomic.Value
	loginPaths     atomic.Value
	streamingPaths atomic.Value // stores *radix.Tree for streaming paths
	l              sync.RWMutex
}

type wildcardPath struct {
	// this sits in the hot path of requests so we are micro-optimizing by
	// storing pre-split slices of path segments
	segments []string
	isPrefix bool
}

// loginPathsEntry is used to hold the routeEntry loginPaths
type loginPathsEntry struct {
	paths         *radix.Tree
	wildcardPaths []wildcardPath
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

	// Build the paths
	paths := new(logical.Paths)
	if backend != nil {
		specialPaths := backend.SpecialPaths()
		if specialPaths != nil {
			paths = specialPaths
		}
	}

	// Create a mount entry
	re := &routeEntry{
		tainted:       mountEntry.Tainted,
		backend:       backend,
		mountEntry:    mountEntry,
		storagePrefix: storageView.Prefix(),
		storageView:   storageView,
	}

	re.rootPaths.Store(pathsToRadix(paths.Root))
	loginPathsEntry, err := parseUnauthenticatedPaths(paths.Unauthenticated)
	if err != nil {
		return err
	}
	re.loginPaths.Store(loginPathsEntry)
	re.streamingPaths.Store(pathsToRadix(paths.Stream))

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

func (r *Router) routeInternal(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Find the mount point
	r.mu.RLock()
	adjustedPath := req.Path
	mount, raw, ok := r.root.LongestPrefix(ns.Path + adjustedPath)
	if !ok && !strings.HasSuffix(adjustedPath, "/") {
		// Re-check for a backend by appending a slash. This lets "foo" mean
		// "foo/" at the root level which is almost always what we want.
		adjustedPath += "/"
		mount, raw, ok = r.root.LongestPrefix(ns.Path + adjustedPath)
	}
	r.mu.RUnlock()
	if !ok {
		return logical.ErrorResponse(logical.ErrNotFoundf("no handler for route %q. route entry not found.", req.Path)), sdklogical.ErrUnsupportedPath
	}
	req.Path = adjustedPath
	re := raw.(*routeEntry)

	re.l.RLock()
	defer re.l.RUnlock()

	if re.backend == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("no handler for route %q. route entry found, but backend is nil.", req.Path)), sdklogical.ErrUnsupportedPath
	}

	// If the path or namespace is tainted, we reject any operation
	if re.tainted || ns.Tainted {
		return logical.ErrorResponse(logical.ErrForbiddenf("no handler for route %q on namespace %q. route entry or namespace is tainted.", req.Path, ns.Path)), sdklogical.ErrUnsupportedPath
	}

	// Adjust the path to exclude the routing prefix
	// The mount includes the namespace prefix, so we need to trim using the full path
	// ns1/ + sys/policies/test - ns1/sys/ = policies/test
	req.Path = strings.TrimPrefix(ns.Path+req.Path, mount)
	req.MountPoint = mount
	req.MountType = re.mountEntry.Type
	req.MountClass = re.mountEntry.Class
	req.MountAccessor = re.mountEntry.Accessor

	return re.backend.HandleRequest(ctx, req)

}

// Route is used to route a given request
func (r *Router) Route(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	return r.routeInternal(ctx, req)
}

// RouteExistenceCheck is used to route a given existence check request
func (r *Router) RouteExistenceCheck(ctx context.Context, req *logical.Request) (*logical.Response, bool, bool, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, false, false, err
	}

	// Find the mount point
	r.mu.RLock()
	adjustedPath := req.Path
	mount, raw, ok := r.root.LongestPrefix(ns.Path + adjustedPath)
	if !ok && !strings.HasSuffix(adjustedPath, "/") {
		// Re-check for a backend by appending a slash
		adjustedPath += "/"
		mount, raw, ok = r.root.LongestPrefix(ns.Path + adjustedPath)
	}
	r.mu.RUnlock()
	if !ok {
		return nil, false, false, sdklogical.ErrUnsupportedPath
	}

	re := raw.(*routeEntry)
	re.l.RLock()
	defer re.l.RUnlock()

	if re.backend == nil {
		return nil, false, false, sdklogical.ErrUnsupportedPath
	}

	// If tainted, we reject any operation
	if re.tainted || ns.Tainted {
		return nil, false, false, sdklogical.ErrUnsupportedPath
	}

	// Adjust the path to exclude the routing prefix
	origPath := req.Path
	req.Path = strings.TrimPrefix(ns.Path+adjustedPath, mount)
	req.MountPoint = mount
	req.MountType = re.mountEntry.Type
	req.MountClass = re.mountEntry.Class
	req.MountAccessor = re.mountEntry.Accessor

	// Perform the existence check
	checkFound, exists, err := re.backend.HandleExistenceCheck(ctx, req)

	// Restore the original path
	req.Path = origPath

	return nil, checkFound, exists, err
}

// LoginPath checks if the given path is used for logins
// Matching Priority
//  1. prefix
//  2. exact
//  3. wildcard
func (r *Router) LoginPath(ctx context.Context, path string) bool {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return false
	}

	adjustedPath := ns.Path + path

	r.mu.RLock()
	mount, raw, ok := r.root.LongestPrefix(adjustedPath)
	r.mu.RUnlock()
	if !ok {
		return false
	}

	re := raw.(*routeEntry)

	re.l.RLock()
	defer re.l.RUnlock()

	// Trim to get remaining path
	remain := strings.TrimPrefix(adjustedPath, mount)

	// Check the loginPaths of this backend
	pe := re.loginPaths.Load().(*loginPathsEntry)
	match, raw, ok := pe.paths.LongestPrefix(remain)
	if !ok && len(pe.wildcardPaths) == 0 {
		// no match found
		return false
	}

	if ok {
		prefixMatch := raw.(bool)
		if prefixMatch {
			// Handle the prefix match case
			return strings.HasPrefix(remain, match)
		}
		if match == remain {
			// Handle the exact match case
			return true
		}
	}

	// check Login Paths containing wildcards
	reqPathParts := strings.Split(remain, "/")
	for _, w := range pe.wildcardPaths {
		if pathMatchesWildcardPath(reqPathParts, w.segments, w.isPrefix) {
			return true
		}
	}
	return false
}

// RootPath checks if the given path requires root privileges
func (r *Router) RootPath(ctx context.Context, path string) bool {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return false
	}

	adjustedPath := ns.Path + path

	r.mu.RLock()
	mount, raw, ok := r.root.LongestPrefix(adjustedPath)
	r.mu.RUnlock()
	if !ok {
		return false
	}
	re := raw.(*routeEntry)

	re.l.RLock()
	defer re.l.RUnlock()

	// Trim to get remaining path
	remain := strings.TrimPrefix(adjustedPath, mount)

	// Check the rootPaths of this backend
	rootPaths := re.rootPaths.Load().(*radix.Tree)
	match, raw, ok := rootPaths.LongestPrefix(remain)
	if !ok {
		return false
	}
	prefixMatch := raw.(bool)

	// Handle the prefix match case
	if prefixMatch {
		return strings.HasPrefix(remain, match)
	}

	// Handle the exact match case
	return match == remain
}

// StreamingPath checks if the given path is a streaming path.
// Streaming paths should not have their request body parsed.
func (r *Router) StreamingPath(ctx context.Context, path string) bool {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return false
	}

	adjustedPath := ns.Path + path

	r.mu.RLock()
	mount, raw, ok := r.root.LongestPrefix(adjustedPath)
	r.mu.RUnlock()
	if !ok {
		return false
	}
	re := raw.(*routeEntry)

	re.l.RLock()
	defer re.l.RUnlock()

	// Trim to get remaining path
	remain := strings.TrimPrefix(adjustedPath, mount)

	// Check the streamingPaths of this backend
	streamingPaths := re.streamingPaths.Load().(*radix.Tree)
	match, raw, ok := streamingPaths.LongestPrefix(remain)
	if !ok {
		return false
	}
	prefixMatch := raw.(bool)

	// Handle the prefix match case
	if prefixMatch {
		return strings.HasPrefix(remain, match)
	}

	// Handle the exact match case
	return match == remain
}

// pathMatchesWildcardPath returns true if the path made up of the path slice
// matches the given wildcard path slice
func pathMatchesWildcardPath(path, wcPath []string, isPrefix bool) bool {
	if len(wcPath) == 0 {
		return false
	}

	if len(path) < len(wcPath) {
		// check if the path coming in is shorter; if so it can't match
		return false
	}
	if !isPrefix && len(wcPath) != len(path) {
		// If it's not a prefix we expect the same number of segments
		return false
	}

	for i, wcPathPart := range wcPath {
		switch {
		case wcPathPart == "+":
		case wcPathPart == path[i]:
		case isPrefix && i == len(wcPath)-1 && strings.HasPrefix(path[i], wcPathPart):
		default:
			// we encountered segments that did not match
			return false
		}
	}
	return true
}

// parseUnauthenticatedPaths converts a list of special paths to a
// loginPathsEntry
func parseUnauthenticatedPaths(paths []string) (*loginPathsEntry, error) {
	var tempPaths []string
	tempWildcardPaths := make([]wildcardPath, 0)
	for _, path := range paths {
		if ok, err := isValidUnauthenticatedPath(path); !ok {
			return nil, err
		}

		if strings.Contains(path, "+") {
			// Paths with wildcards are not stored in the radix tree because
			// the radix tree does not handle wildcards in the middle of strings.
			isPrefix := false
			if path[len(path)-1] == '*' {
				isPrefix = true
				path = path[0 : len(path)-1]
			}
			// We are micro-optimizing by storing pre-split slices of path segments
			wcPath := wildcardPath{segments: strings.Split(path, "/"), isPrefix: isPrefix}
			tempWildcardPaths = append(tempWildcardPaths, wcPath)
		} else {
			// accumulate paths that do not contain wildcards
			// to be stored in the radix tree
			tempPaths = append(tempPaths, path)
		}
	}

	return &loginPathsEntry{
		paths:         pathsToRadix(tempPaths),
		wildcardPaths: tempWildcardPaths,
	}, nil
}

// pathsToRadix converts a list of special paths to a radix tree.
func pathsToRadix(paths []string) *radix.Tree {
	tree := radix.New()
	for _, path := range paths {
		// Check if this is a prefix or exact match
		prefixMatch := len(path) >= 1 && path[len(path)-1] == '*'
		if prefixMatch {
			path = path[:len(path)-1]
		}

		tree.Insert(path, prefixMatch)
	}

	return tree
}

func wildcardError(path, msg string) error {
	return fmt.Errorf("path %q: invalid use of wildcards %s", path, msg)
}

func isValidUnauthenticatedPath(path string) (bool, error) {
	switch {
	case strings.Count(path, "*") > 1:
		return false, wildcardError(path, "(multiple '*' is forbidden)")
	case strings.Contains(path, "+*"):
		return false, wildcardError(path, "('+*' is forbidden)")
	case strings.Contains(path, "*") && path[len(path)-1] != '*':
		return false, wildcardError(path, "('*' is only allowed at the end of a path)")
	case wcAdjacentNonSlashRegEx(path):
		return false, wildcardError(path, "('+' is not allowed next to a non-slash)")
	}
	return true, nil
}
