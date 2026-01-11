// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package framework

import (
	"bytes"
	"strings"
	"text/template"
)

func executeTemplate(tpl string, data interface{}) (string, error) {
	t := template.New("t").Funcs(template.FuncMap{
		"indent": func(spaces int, s string) string {
			prefix := strings.Repeat(" ", spaces)
			lines := strings.Split(s, "\n")
			for i, line := range lines {
				if line != "" {
					lines[i] = prefix + line
				}
			}
			return strings.Join(lines, "\n")
		},
	})

	t, err := t.Parse(tpl)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
