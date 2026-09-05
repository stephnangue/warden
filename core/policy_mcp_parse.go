// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"

	"github.com/stephnangue/warden/internal/namespace"
)

// The MCP policy grammar is parsed with HCL v2 rather than the v1 parser the
// CBP grammar inherited. Two properties matter here and neither is available
// in v1: unsupported attributes and blocks are rejected by default, and a
// repeated block is a hard error instead of a silent field-wise merge.
//
// Both matter asymmetrically for a restrictive policy. A typo in `allowed`
// merely denies more than intended — noisy but safe. A typo in `denied` would
// leave the deny list empty and silently widen the policy, which is the one
// failure mode this grammar must not have.
//
// The parsers stay independent, but the canonical path key does not: both call
// normalizePathPattern, so the CBP and MCP indexes cannot disagree on which
// requests a stanza covers.

// mcpPolicyDoc is the decode shape of a whole MCP policy document.
type mcpPolicyDoc struct {
	Name  string             `hcl:"name,optional"`
	Paths []mcpPolicyPathHCL `hcl:"path,block"`
}

// mcpPolicyPathHCL is one `path "..." { }` stanza of an MCP policy. There is no
// capabilities key: an MCP policy grants nothing, it only narrows what a
// capability-based grant already allows.
type mcpPolicyPathHCL struct {
	Path string `hcl:"path,label"`

	Comment    string `hcl:"comment,optional"`
	Expiration string `hcl:"expiration,optional"`

	Methods   *mcpFamilyHCL `hcl:"methods,block"`
	Tools     *mcpFamilyHCL `hcl:"tools,block"`
	Resources *mcpFamilyHCL `hcl:"resources,block"`
	Prompts   *mcpFamilyHCL `hcl:"prompts,block"`

	// Condition is the per-call CEL expression. It spans every family and is
	// evaluated once per call, so it belongs to the stanza rather than to any
	// one family block.
	Condition string `hcl:"condition,optional"`
}

// mcpFamilyHCL is one family block: methods, tools, resources or prompts.
type mcpFamilyHCL struct {
	Allowed []string `hcl:"allowed,optional"`
	Denied  []string `hcl:"denied,optional"`
}

// lists returns the (allowed, denied) pair for a family block, tolerating a
// nil receiver so an omitted block reads the same as an empty one.
func (f *mcpFamilyHCL) lists() (allowed, denied []string) {
	if f == nil {
		return nil, nil
	}
	return f.Allowed, f.Denied
}

// flatten converts a stanza's family blocks into the flat rule shape that
// canonicaliseMCPRules validates, so wildcard checking, lowercasing and CEL
// compilation live in one place no matter how the document spells them.
func (s *mcpPolicyPathHCL) flatten() *MCPRulesHCL {
	h := &MCPRulesHCL{Condition: s.Condition}
	h.AllowedMethods, h.DeniedMethods = s.Methods.lists()
	h.AllowedTools, h.DeniedTools = s.Tools.lists()
	h.AllowedResources, h.DeniedResources = s.Resources.lists()
	h.AllowedPrompts, h.DeniedPrompts = s.Prompts.lists()
	return h
}

// ParseMCPPolicy parses an MCP policy document into an intermediary Policy.
//
// An MCP policy is keyed by request path exactly as a CBP policy is, but each
// stanza groups its rules by the thing being governed — methods, tools,
// resources, prompts — and carries no capabilities. The result is purely
// restrictive: it grants nothing on its own, and its rules are ANDed with the
// CBP decision at request time.
func ParseMCPPolicy(ns *namespace.Namespace, rules string) (*Policy, error) {
	body, err := parseMCPBody([]byte(rules))
	if err != nil {
		return nil, err
	}

	var doc mcpPolicyDoc
	if diags := gohcl.DecodeBody(body, nil, &doc); diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse policy: %s", diags.Error())
	}

	p := &Policy{
		Name:      doc.Name,
		Raw:       rules,
		Type:      PolicyTypeMCP,
		namespace: ns,
	}

	paths := make([]*PathRules, 0, len(doc.Paths))
	for i := range doc.Paths {
		stanza := &doc.Paths[i]

		var expiration time.Time
		if stanza.Expiration != "" {
			exp, err := parseutil.ParseAbsoluteTime(stanza.Expiration)
			if err != nil {
				return nil, fmt.Errorf("path %q: invalid expiration time: %w", stanza.Path, err)
			}

			// An expired stanza is dropped at parse, mechanically the same
			// treatment a CBP path stanza gets — but not the same direction.
			// Dropping an expired CBP stanza removes a grant, which fails
			// closed; dropping an expired MCP stanza removes a restriction.
			// A lapsed tool contract must therefore stop traffic rather than
			// free it, which is what the absence deny-by-default provides: no
			// stanza in scope for an MCP-shaped request is a denial. Until that
			// rule is in place, an expired stanza leaves its path ungoverned.
			if time.Now().After(exp) {
				continue
			}
			expiration = exp
		}

		normPath, isPrefix, hasSegmentWildcards, err := normalizePathPattern(ns, stanza.Path)
		if err != nil {
			return nil, err
		}

		rules, err := canonicaliseMCPRules(stanza.flatten())
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", stanza.Path, err)
		}

		paths = append(paths, &PathRules{
			Path:                normPath,
			IsPrefix:            isPrefix,
			HasSegmentWildcards: hasSegmentWildcards,
			Expiration:          expiration,
			Permissions: &CBPPermissions{
				MCP: []*CBPMCPRules{rules},
			},
		})
	}

	p.Paths = paths
	return p, nil
}

// parseMCPBody parses a policy document as either native HCL or JSON, matching
// the "HCL or JSON format" contract the policy API advertises. The format is
// sniffed the same way the CBP parser sniffs it: a leading '{' means JSON.
func parseMCPBody(src []byte) (hcl.Body, error) {
	if strings.HasPrefix(strings.TrimSpace(string(src)), "{") {
		file, diags := hcljson.Parse(src, "policy.json")
		if diags.HasErrors() {
			return nil, fmt.Errorf("failed to parse policy: %s", diags.Error())
		}
		return file.Body, nil
	}

	file, diags := hclsyntax.ParseConfig(src, "policy.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse policy: %s", diags.Error())
	}
	return file.Body, nil
}
