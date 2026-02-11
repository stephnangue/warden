package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Resource is the structure returned by the system backend within Warden.
type Resource struct {
	// Data is the actual contents of the resource. The format of the data
	// is arbitrary and depend on the resource.
	Data map[string]any `json:"data"`
}

// ParseResource is used to parse a resource value from JSON from an io.Reader.
func ParseResource(r io.Reader) (*Resource, error) {
	// First read the data into a buffer. Not super efficient but we want to
	// know if we actually have a body or not.
	var buf bytes.Buffer

	// io.Reader is treated like a stream and cannot be read
	// multiple times. Duplicating this stream using TeeReader
	// to use this data in case there is no top-level data from
	// api response
	var teebuf bytes.Buffer
	tee := io.TeeReader(r, &teebuf)

	_, err := buf.ReadFrom(tee)
	if err != nil {
		return nil, err
	}
	if buf.Len() == 0 {
		return nil, nil
	}

	// First decode the JSON into a map[string]interface{}
	var resource Resource
	dec := json.NewDecoder(&buf)
	dec.UseNumber()
	if err := dec.Decode(&resource); err != nil {
		return nil, err
	}

	// If the resource is null, add raw data to resource data if present
	if resource.Data == nil {
		data := make(map[string]interface{})
		dec := json.NewDecoder(&teebuf)
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return nil, err
		}
		errRaw, errPresent := data["errors"]

		// if only errors are present in the resp.Body return nil
		// to return value not found as it does not have any raw data
		if len(data) == 1 && errPresent {
			return nil, nil
		}

		// if errors are present along with raw data return the error
		if errPresent {
			var errStrArray []string
			errBytes, err := json.Marshal(errRaw)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(errBytes, &errStrArray); err != nil {
				return nil, err
			}
			return nil, errors.New(strings.Join(errStrArray, " "))
		}

		// if any raw data is present in resp.Body, add it to secret
		if len(data) > 0 {
			resource.Data = data
		}
	}

	return &resource, nil
}