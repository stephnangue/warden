package core

// MountProviderInput represents the input for mounting a provider
type MountProviderInput struct {
	Path        string         `path:"path" minLength:"1" maxLength:"256" pattern:"^[a-zA-Z0-9_-]+$" doc:"Mount path (alphanumeric, underscore, hyphen only)" example:"my-aws"`
	Type        string         `json:"type" minLength:"1" maxLength:"50" pattern:"^[a-z0-9_]+$" doc:"Provider type (e.g., aws, gcp)" example:"aws"`
	Description string         `json:"description" maxLength:"500" doc:"Human-readable description" example:"Production AWS provider"`
	Config      map[string]any `json:"config" doc:"Provider-specific configuration (validated by provider factory)"`
}

// MountProviderOutput represents the output after mounting a provider
type MountProviderOutput struct {
	Body struct {
		Accessor string `json:"accessor" doc:"Unique mount accessor"`
		Path     string `json:"path" doc:"Mounted path"`
		Message  string `json:"message" doc:"Success message"`
	}
}

// GetMountInput represents the input for getting mount information
type GetMountInput struct {
	Path string `path:"path" minLength:"1" maxLength:"256" doc:"Mount path to query" example:"my-aws"`
}

// GetMountOutput represents the output for mount information
type GetMountOutput struct {
	Body struct {
		Class       string         `json:"class" doc:"Mount class"`
		Type        string         `json:"type" doc:"Mount type"`
		Path        string         `json:"path" doc:"Mount path"`
		Description string         `json:"description" doc:"Description"`
		Accessor    string         `json:"accessor" doc:"Unique accessor"`
		Tainted     bool           `json:"tainted" doc:"Taint status"`
		Config      map[string]any `json:"config" doc:"Configuration"`
	}
}

// UnmountProviderInput represents the input for unmounting a provider
type UnmountProviderInput struct {
	Path string `path:"path" minLength:"1" maxLength:"256" pattern:"^[a-zA-Z0-9_-]+$" doc:"Mount path to unmount" example:"my-aws"`
}

// UnmountProviderOutput represents the output after unmounting
type UnmountProviderOutput struct {
	Body struct {
		Message string `json:"message" doc:"Success message"`
	}
}

// ListMountsInput represents the input for listing mounts
type ListMountsInput struct {
	Class string `query:"class" enum:"provider,auth,audit,system" doc:"Filter by mount class" example:"provider"`
}

// ListMountsOutput represents the output for listing mounts
type ListMountsOutput struct {
	Body struct {
		Mounts map[string]MountInfo `json:"mounts" doc:"Map of path to mount info"`
	}
}

// MountInfo represents mount metadata
type MountInfo struct {
	Class       string         `json:"class" doc:"Mount class"`
	Type        string         `json:"type" doc:"Mount type"`
	Description string         `json:"description" doc:"Description"`
	Accessor    string         `json:"accessor" doc:"Unique accessor"`
	Config      map[string]any `json:"config" doc:"Configuration"`
}
