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

// Credential Source Models

// CreateCredentialSourceInput represents the input for creating a credential source
type CreateCredentialSourceInput struct {
	Name string `path:"name" minLength:"1" maxLength:"256" pattern:"^[a-zA-Z0-9_-]+$" doc:"Credential source name" example:"vault-prod"`
	Body struct {
		Type   string            `json:"type" minLength:"1" maxLength:"50" pattern:"^[a-z0-9_]+$" doc:"Source type (e.g., local, hashicorp_vault, aws_secret_manager)" example:"hashicorp_vault"`
		Config map[string]string `json:"config,omitempty" doc:"Source-specific configuration (address, token, etc.)"`
	}
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// CreateCredentialSourceOutput represents the output after creating a credential source
type CreateCredentialSourceOutput struct {
	Body struct {
		Name    string            `json:"name" doc:"Credential source name"`
		Type    string            `json:"type" doc:"Source type"`
		Config  map[string]string `json:"config,omitempty" doc:"Source configuration"`
		Message string            `json:"message" doc:"Success message"`
	}
}

// GetCredentialSourceInput represents the input for getting a credential source
type GetCredentialSourceInput struct {
	Name            string `path:"name" minLength:"1" maxLength:"256" doc:"Credential source name" example:"vault-prod"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// GetCredentialSourceOutput represents the output for credential source information
type GetCredentialSourceOutput struct {
	Body struct {
		Name   string            `json:"name" doc:"Credential source name"`
		Type   string            `json:"type" doc:"Source type"`
		Config map[string]string `json:"config,omitempty" doc:"Source configuration"`
	}
}

// ListCredentialSourcesInput represents the input for listing credential sources
type ListCredentialSourcesInput struct {
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// ListCredentialSourcesOutput represents the output for listing credential sources
type ListCredentialSourcesOutput struct {
	Body struct {
		Sources []CredentialSourceInfo `json:"sources" doc:"List of credential sources"`
	}
}

// CredentialSourceInfo represents credential source metadata
type CredentialSourceInfo struct {
	Name   string            `json:"name" doc:"Credential source name"`
	Type   string            `json:"type" doc:"Source type"`
	Config map[string]string `json:"config,omitempty" doc:"Source configuration"`
}

// UpdateCredentialSourceInput represents the input for updating a credential source
type UpdateCredentialSourceInput struct {
	Name string `path:"name" minLength:"1" maxLength:"256" doc:"Credential source name" example:"vault-prod"`
	Body struct {
		Config map[string]string `json:"config,omitempty" doc:"Updated configuration"`
	}
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// UpdateCredentialSourceOutput represents the output after updating a credential source
type UpdateCredentialSourceOutput struct {
	Body struct {
		Name    string `json:"name" doc:"Credential source name"`
		Message string `json:"message" doc:"Success message"`
	}
}

// DeleteCredentialSourceInput represents the input for deleting a credential source
type DeleteCredentialSourceInput struct {
	Name            string `path:"name" minLength:"1" maxLength:"256" doc:"Credential source name" example:"vault-prod"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// DeleteCredentialSourceOutput represents the output after deleting a credential source
type DeleteCredentialSourceOutput struct {
	Body struct {
		Message string `json:"message" doc:"Success message"`
	}
}

// Credential Spec Models

// CreateCredentialSpecInput represents the input for creating a credential spec
type CreateCredentialSpecInput struct {
	Name string `path:"name" minLength:"1" maxLength:"256" pattern:"^[a-zA-Z0-9_-]+$" doc:"Credential spec name" example:"db-admin"`
	Body struct {
		Type         string            `json:"type" minLength:"1" maxLength:"50" pattern:"^[a-z0-9_]+$" doc:"Credential type (e.g., database_userpass, aws_access_keys)" example:"database_userpass"`
		SourceName   string            `json:"source_name" minLength:"1" maxLength:"256" doc:"Reference to credential source" example:"vault-prod"`
		SourceParams map[string]string `json:"source_params,omitempty" doc:"Type-specific parameters (path, role_name, etc.)"`
		MinTTL       int64             `json:"min_ttl" minimum:"0" doc:"Minimum TTL in seconds for issued credentials" example:"300"`
		MaxTTL       int64             `json:"max_ttl" minimum:"0" doc:"Maximum TTL in seconds for issued credentials" example:"3600"`
		TargetName   string            `json:"target_name,omitempty" maxLength:"256" doc:"Target binding for audit/routing" example:"prod-db"`
	}
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// CreateCredentialSpecOutput represents the output after creating a credential spec
type CreateCredentialSpecOutput struct {
	Body struct {
		Name         string            `json:"name" doc:"Credential spec name"`
		Type         string            `json:"type" doc:"Credential type"`
		SourceName   string            `json:"source_name" doc:"Reference to credential source"`
		SourceParams map[string]string `json:"source_params,omitempty" doc:"Type-specific parameters"`
		MinTTL       int64             `json:"min_ttl" doc:"Minimum TTL in seconds"`
		MaxTTL       int64             `json:"max_ttl" doc:"Maximum TTL in seconds"`
		TargetName   string            `json:"target_name,omitempty" doc:"Target binding"`
		Message      string            `json:"message" doc:"Success message"`
	}
}

// GetCredentialSpecInput represents the input for getting a credential spec
type GetCredentialSpecInput struct {
	Name            string `path:"name" minLength:"1" maxLength:"256" doc:"Credential spec name" example:"db-admin"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// GetCredentialSpecOutput represents the output for credential spec information
type GetCredentialSpecOutput struct {
	Body struct {
		Name         string            `json:"name" doc:"Credential spec name"`
		Type         string            `json:"type" doc:"Credential type"`
		SourceName   string            `json:"source_name" doc:"Reference to credential source"`
		SourceParams map[string]string `json:"source_params,omitempty" doc:"Type-specific parameters"`
		MinTTL       int64             `json:"min_ttl" doc:"Minimum TTL in seconds"`
		MaxTTL       int64             `json:"max_ttl" doc:"Maximum TTL in seconds"`
		TargetName   string            `json:"target_name,omitempty" doc:"Target binding"`
	}
}

// ListCredentialSpecsInput represents the input for listing credential specs
type ListCredentialSpecsInput struct {
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// ListCredentialSpecsOutput represents the output for listing credential specs
type ListCredentialSpecsOutput struct {
	Body struct {
		Specs []CredentialSpecInfo `json:"specs" doc:"List of credential specs"`
	}
}

// CredentialSpecInfo represents credential spec metadata
type CredentialSpecInfo struct {
	Name         string            `json:"name" doc:"Credential spec name"`
	Type         string            `json:"type" doc:"Credential type"`
	SourceName   string            `json:"source_name" doc:"Reference to credential source"`
	SourceParams map[string]string `json:"source_params,omitempty" doc:"Type-specific parameters"`
	MinTTL       int64             `json:"min_ttl" doc:"Minimum TTL in seconds"`
	MaxTTL       int64             `json:"max_ttl" doc:"Maximum TTL in seconds"`
	TargetName   string            `json:"target_name,omitempty" doc:"Target binding"`
}

// UpdateCredentialSpecInput represents the input for updating a credential spec
type UpdateCredentialSpecInput struct {
	Name string `path:"name" minLength:"1" maxLength:"256" doc:"Credential spec name" example:"db-admin"`
	Body struct {
		SourceParams map[string]string `json:"source_params,omitempty" doc:"Updated type-specific parameters"`
		MinTTL       *int64            `json:"min_ttl,omitempty" minimum:"0" doc:"Updated minimum TTL in seconds"`
		MaxTTL       *int64            `json:"max_ttl,omitempty" minimum:"0" doc:"Updated maximum TTL in seconds"`
	}
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// UpdateCredentialSpecOutput represents the output after updating a credential spec
type UpdateCredentialSpecOutput struct {
	Body struct {
		Name    string `json:"name" doc:"Credential spec name"`
		Message string `json:"message" doc:"Success message"`
	}
}

// DeleteCredentialSpecInput represents the input for deleting a credential spec
type DeleteCredentialSpecInput struct {
	Name            string `path:"name" minLength:"1" maxLength:"256" doc:"Credential spec name" example:"db-admin"`
	WardenNamespace string `header:"X-Warden-Namespace"`
}

// DeleteCredentialSpecOutput represents the output after deleting a credential spec
type DeleteCredentialSpecOutput struct {
	Body struct {
		Message string `json:"message" doc:"Success message"`
	}
}
