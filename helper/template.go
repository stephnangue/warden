package helper

import (
	"bytes"
	"embed"
	"text/template"
)

// process applies the data structure 'vars' onto an already
// parsed template 't', and returns the resulting string.
func process(t *template.Template, vars any) string {
    var tmplBytes bytes.Buffer

    err := t.Execute(&tmplBytes, vars)
    if err != nil {
        panic(err)
    }
    return tmplBytes.String()
}

func InterpolateString(str string, vars any) string {
    tmpl, err := template.New("tmpl").Parse(str)

    if err != nil {
        panic(err)
    }
    return process(tmpl, vars)
}

func InterpolateFile(fileName string, vars any) string {
    tmpl, err := template.ParseFiles(fileName)

    if err != nil {
        panic(err)
    }
    return process(tmpl, vars)
}

func InterpolateFS(fileSystem embed.FS, filePath string, vars any) string {
    tmpl, err := template.ParseFS(fileSystem, filePath)

    if err != nil {
        panic(err)
    }
    return process(tmpl, vars)
}