package httpproxy

import (
	"strings"

	"github.com/hashicorp/go-multierror"
)

// WardenErrorMessage is the text of a gateway failure Warden raised itself, marked
// as Warden's so a client cannot mistake it for an error from the upstream. A
// renderer puts it where the upstream's error shape carries its message.
//
// Core collects some failures in a multierror, whose text is a bulleted list
// ("1 error occurred:\n\t* permission denied\n\n"); the messages are kept and
// joined, the bullets dropped.
func WardenErrorMessage(err error) string {
	if err == nil {
		return "Warden: request failed"
	}
	if merr, ok := err.(*multierror.Error); ok && len(merr.Errors) > 0 {
		msgs := make([]string, len(merr.Errors))
		for i, e := range merr.Errors {
			msgs[i] = e.Error()
		}
		return "Warden: " + strings.Join(msgs, "; ")
	}
	return "Warden: " + err.Error()
}
