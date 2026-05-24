package config

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Warner is the minimal sink used to surface parser warnings for
// unknown HCL attributes and blocks. Single-string signature keeps
// adapters trivial. cmd/server passes StderrWarner so warnings appear
// immediately at startup — buffering until the warden GatedLogger is
// built would lose them if config load fails for any other reason.
type Warner interface {
	Warn(msg string)
}

type nopWarner struct{}

func (nopWarner) Warn(string) {}

// StderrWarner writes warnings directly to os.Stderr with a stable
// prefix. Suitable for the early config-load path where the warden
// logger has not been constructed yet.
type StderrWarner struct{}

func (StderrWarner) Warn(msg string) {
	fmt.Fprintln(os.Stderr, "[WARN] config: "+msg)
}

// decodeConfig parses HCL bytes into a *Config, warning-and-ignoring any
// attribute or block not declared on Config or its known nested block
// types (listener, storage, seal, audit). Foreign-style top-level keys
// (`ui`, `cluster_name`, `default_lease_ttl`, etc.) and unknown attrs
// inside known blocks are dropped with a warning rather than failing the
// parse.
func decodeConfig(filename string, src []byte, warner Warner) (*Config, error) {
	if warner == nil {
		warner = nopWarner{}
	}

	file, diags := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diags
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("internal: unexpected HCL body type %T", file.Body)
	}

	pruneBody(body, warner)

	var cfg Config
	if diags := gohcl.DecodeBody(body, nil, &cfg); diags.HasErrors() {
		return nil, diags
	}
	return &cfg, nil
}

// pruneBody walks body against the schemas derived from the Config struct
// hierarchy, deleting any attribute or block that gohcl would otherwise
// reject as unsupported. Each removal emits a Warn() call carrying the
// source range so operators can spot stale or typo'd keys.
func pruneBody(body *hclsyntax.Body, warner Warner) {
	pruneAgainst(body, configSchema, warner)
	for _, blk := range body.Blocks {
		inner, ok := nestedSchemas[blk.Type]
		if !ok {
			continue
		}
		pruneAgainst(blk.Body, inner, warner)
	}
}

func pruneAgainst(body *hclsyntax.Body, schema *hcl.BodySchema, warner Warner) {
	knownAttrs := make(map[string]struct{}, len(schema.Attributes))
	for _, a := range schema.Attributes {
		knownAttrs[a.Name] = struct{}{}
	}
	knownBlocks := make(map[string]struct{}, len(schema.Blocks))
	for _, b := range schema.Blocks {
		knownBlocks[b.Type] = struct{}{}
	}

	for name, attr := range body.Attributes {
		if _, ok := knownAttrs[name]; ok {
			continue
		}
		warner.Warn(fmt.Sprintf("ignoring unknown attribute %q at %s", name, attr.SrcRange))
		delete(body.Attributes, name)
	}

	kept := body.Blocks[:0]
	for _, blk := range body.Blocks {
		if _, ok := knownBlocks[blk.Type]; ok {
			kept = append(kept, blk)
			continue
		}
		warner.Warn(fmt.Sprintf("ignoring unknown block %q at %s", blk.Type, blk.DefRange()))
	}
	body.Blocks = kept
}

var (
	configSchema   *hcl.BodySchema
	nestedSchemas  map[string]*hcl.BodySchema
)

func init() {
	configSchema, _ = gohcl.ImpliedBodySchema(Config{})
	listenerSchema, _ := gohcl.ImpliedBodySchema(ListenerBlock{})
	storageSchema, _ := gohcl.ImpliedBodySchema(StorageBlock{})
	sealSchema, _ := gohcl.ImpliedBodySchema(KMS{})
	auditSchema, _ := gohcl.ImpliedBodySchema(AuditBlock{})
	nestedSchemas = map[string]*hcl.BodySchema{
		"listener": listenerSchema,
		"storage":  storageSchema,
		"seal":     sealSchema,
		"audit":    auditSchema,
	}
}
