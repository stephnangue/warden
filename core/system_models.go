package core

// MountProviderInput represents the input for mounting a provider
type MountProviderInput struct {
	Path string `path:"path" minLength:"1" maxLength:"256" doc:"The path to mount to" example:"aws-prod"`
	Body struct {
		Type        string         `json:"type" minLength:"1" maxLength:"50" pattern:"^[a-z0-9_]+$" doc:"Provider type (e.g., aws, gcp)" example:"aws"`
		Description string         `json:"description,omitempty" maxLength:"500" doc:"Human-readable description" example:"Production AWS provider"`
		Config      map[string]any `json:"config,omitempty" doc:"Provider-specific configuration (validated by provider factory)"`
	}
	WardenNamespace string `header:"X-Warden-Namespace"`
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
	Path            string `path:"path" minLength:"1" maxLength:"256" doc:"Path to query" example:"aws-production"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// GetMountOutput represents the output for mount information
type GetMountOutput struct {
	Body struct {
		Type        string         `json:"type" doc:"Mount type"`
		Path        string         `json:"path" doc:"Mount path"`
		Description string         `json:"description" doc:"Description"`
		Accessor    string         `json:"accessor" doc:"Unique accessor"`
		Config      map[string]any `json:"config" doc:"Configuration"`
	}
}

// UnmountProviderInput represents the input for unmounting a provider
type UnmountProviderInput struct {
	Path            string `path:"path" minLength:"1" maxLength:"256" doc:"Mount path to unmount" example:"aws-production"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// UnmountProviderOutput represents the output after unmounting
type UnmountProviderOutput struct {
	Body struct {
		Message string `json:"message" doc:"Success message"`
	}
}

// ListMountsInput represents the input for listing mounts
type ListMountsInput struct {
	Class           string `query:"class" enum:"provider,auth,audit,system" doc:"Filter by mount class" example:"provider"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// ListMountsOutput represents the output for listing mounts
type ListMountsOutput struct {
	Body struct {
		Mounts map[string]MountInfo `json:"mounts" doc:"Map of path to mount info"`
	}
}

// MountInfo represents mount metadata
type MountInfo struct {
	Type        string         `json:"type" doc:"Mount type"`
	Description string         `json:"description" doc:"Description"`
	Accessor    string         `json:"accessor" doc:"Unique accessor"`
	Config      map[string]any `json:"config" doc:"Configuration"`
}

// TuneProviderInput represents the input for tuning a mount
type TuneProviderInput struct {
	Path            string `path:"path" minLength:"1" maxLength:"256" doc:"Mount path to tune" example:"aws-production"`
	Body            map[string]any
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// TuneProviderOutput represents the output after tuning a mount
type TuneProviderOutput struct {
	Body struct {
		Message string `json:"message" doc:"Success message"`
	}
}

type (
	MountAuthInput    = MountProviderInput
	MountAuthOutput   = MountProviderOutput
	GetAuthInput      = GetMountInput
	UnmountAuthInput  = UnmountProviderInput
	UnmountAuthOutput = UnmountProviderOutput
	ListAuthsInput    = ListMountsInput
	ListAuthsOutput   = ListMountsOutput
	AuthInfo          = MountInfo
	TuneAuthInput     = TuneProviderInput
	TuneAuthOutput    = TuneProviderOutput
)

// CreateNamespaceInput represents the input for creating a namespace
type CreateNamespaceInput struct {
	Path string `path:"path" minLength:"1" maxLength:"256" doc:"The path where the namespace will be created" example:"my-namespace"`
	Body struct {
		CustomMetadata map[string]string `json:"custom_metadata,omitempty" doc:"A map of arbitrary string to string valued user-provided metadata meant to describe the namespace"`
	}
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// CreateNamespaceOutput represents the output after creating a namespace
type CreateNamespaceOutput struct {
	Body struct {
		ID             string            `json:"id" doc:"Namespace ID"`
		Path           string            `json:"path" doc:"Namespace path"`
		CustomMetadata map[string]string `json:"custom_metadata,omitempty" doc:"Custom metadata"`
		Message        string            `json:"message" doc:"Success message"`
	}
}

// GetNamespaceInput represents the input for getting namespace information
type GetNamespaceInput struct {
	Path            string `path:"path" minLength:"1" maxLength:"256" doc:"Namespace path to query" example:"my-namespace"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// GetNamespaceOutput represents the output for namespace information
type GetNamespaceOutput struct {
	Body struct {
		ID             string            `json:"id" doc:"Namespace ID"`
		Path           string            `json:"path" doc:"Namespace path"`
		CustomMetadata map[string]string `json:"custom_metadata,omitempty" doc:"Custom metadata"`
		Tainted        bool              `json:"tainted"`
		Locked         bool              `json:"locked"`
		Uuid           string            `json:"uuid"`
	}
}

// ListNamespacesInput represents the input for listing namespaces
type ListNamespacesInput struct {
	IncludeParent   bool   `query:"include_parent" doc:"Include the parent namespace in the result" example:"false"`
	Recursive       bool   `query:"recursive" doc:"Recursively list all descendant namespaces" example:"false"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// ListNamespacesOutput represents the output for listing namespaces
type ListNamespacesOutput struct {
	Body struct {
		Namespaces []NamespaceInfo `json:"namespaces" doc:"List of namespaces"`
	}
}

// NamespaceInfo represents namespace metadata
type NamespaceInfo struct {
	Path           string            `json:"path" doc:"Namespace path"`
	ID             string            `json:"id" doc:"Namespace ID"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty" doc:"Custom metadata"`
}

// UpdateNamespaceInput represents the input for updating a namespace
type UpdateNamespaceInput struct {
	Path string `path:"path" minLength:"1" maxLength:"256" doc:"Namespace path to update" example:"my-namespace"`
	Body struct {
		CustomMetadata map[string]string `json:"custom_metadata,omitempty" doc:"Updated custom metadata"`
	}
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// UpdateNamespaceOutput represents the output after updating a namespace
type UpdateNamespaceOutput struct {
	Body struct {
		ID             string            `json:"id" doc:"Namespace ID"`
		Path           string            `json:"path" doc:"Namespace path"`
		CustomMetadata map[string]string `json:"custom_metadata,omitempty" doc:"Custom metadata"`
		Message        string            `json:"message" doc:"Success message"`
	}
}

// DeleteNamespaceInput represents the input for deleting a namespace
type DeleteNamespaceInput struct {
	Path            string `path:"path" minLength:"1" maxLength:"256" doc:"Namespace path to delete" example:"my-namespace"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// DeleteNamespaceOutput represents the output after deleting a namespace
type DeleteNamespaceOutput struct {
	Body struct {
		Message string `json:"message" doc:"Success message"`
	}
}
