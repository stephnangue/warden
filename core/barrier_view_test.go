// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestBarrierView_spec(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")
	logical.TestStorage(t, view)
}

func TestBarrierView_BadKeys(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")

	_, err := view.List(context.Background(), "../")
	if err == nil {
		t.Fatal("expected error")
	}

	_, err = view.Get(context.Background(), "../")
	if err == nil {
		t.Fatal("expected error")
	}

	err = view.Delete(context.Background(), "../foo")
	if err == nil {
		t.Fatal("expected error")
	}

	le := &logical.StorageEntry{
		Key:   "../foo",
		Value: []byte("test"),
	}
	err = view.Put(context.Background(), le)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBarrierView(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")

	// Write a key outside of foo/
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	if err := barrier.Put(context.Background(), entry); err != nil {
		t.Fatalf("bad: %v", err)
	}

	// List should have no visibility
	keys, err := view.List(context.Background(), "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("bad: %v", err)
	}

	// Get should have no visibility
	out, err := view.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != nil {
		t.Fatalf("bad: %v", out)
	}

	// Try to put the same entry via the view
	if err := view.Put(context.Background(), entry); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check it is nested
	entry, err = barrier.Get(context.Background(), "foo/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry == nil {
		t.Fatal("missing nested foo/test")
	}

	// Delete nested
	if err := view.Delete(context.Background(), "test"); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the nested key
	entry, err = barrier.Get(context.Background(), "foo/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry != nil {
		t.Fatal("nested foo/test should be gone")
	}

	// Check the non-nested key
	entry, err = barrier.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if entry == nil {
		t.Fatal("root test missing")
	}
}

func TestBarrierView_SubView(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	root := NewBarrierView(barrier, "foo/")
	view := root.SubView("bar/")

	// List should have no visibility
	keys, err := view.List(context.Background(), "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("bad: %v", err)
	}

	// Get should have no visibility
	out, err := view.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != nil {
		t.Fatalf("bad: %v", out)
	}

	// Try to put the same entry via the view
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	if err := view.Put(context.Background(), entry); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check it is nested
	bout, err := barrier.Get(context.Background(), "foo/bar/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if bout == nil {
		t.Fatal("missing nested foo/bar/test")
	}

	// Check for visibility in root
	out, err = root.Get(context.Background(), "bar/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("missing nested bar/test")
	}

	// Delete nested
	if err := view.Delete(context.Background(), "test"); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Check the nested key
	bout, err = barrier.Get(context.Background(), "foo/bar/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if bout != nil {
		t.Fatal("nested foo/bar/test should be gone")
	}
}

func TestBarrierView_Scan(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "view/")

	expect := []string{}
	ent := []*logical.StorageEntry{
		{Key: "foo", Value: []byte("test")},
		{Key: "zip", Value: []byte("test")},
		{Key: "foo/bar", Value: []byte("test")},
		{Key: "foo/zap", Value: []byte("test")},
		{Key: "foo/bar/baz", Value: []byte("test")},
		{Key: "foo/bar/zoo", Value: []byte("test")},
	}

	for _, e := range ent {
		expect = append(expect, e.Key)
		if err := view.Put(context.Background(), e); err != nil {
			t.Fatalf("err: %v", err)
		}
	}

	var out []string
	cb := func(path string) {
		out = append(out, path)
	}

	// Collect the keys
	if err := logical.ScanView(context.Background(), view, cb); err != nil {
		t.Fatalf("err: %v", err)
	}

	sort.Strings(out)
	sort.Strings(expect)
	if !reflect.DeepEqual(out, expect) {
		t.Fatalf("out: %v expect: %v", out, expect)
	}
}

func TestBarrierView_CollectKeys(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "view/")

	expect := []string{}
	ent := []*logical.StorageEntry{
		{Key: "foo", Value: []byte("test")},
		{Key: "zip", Value: []byte("test")},
		{Key: "foo/bar", Value: []byte("test")},
		{Key: "foo/zap", Value: []byte("test")},
		{Key: "foo/bar/baz", Value: []byte("test")},
		{Key: "foo/bar/zoo", Value: []byte("test")},
	}

	for _, e := range ent {
		expect = append(expect, e.Key)
		if err := view.Put(context.Background(), e); err != nil {
			t.Fatalf("err: %v", err)
		}
	}

	// Collect the keys
	out, err := logical.CollectKeys(context.Background(), view)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	sort.Strings(out)
	sort.Strings(expect)
	if !reflect.DeepEqual(out, expect) {
		t.Fatalf("out: %v expect: %v", out, expect)
	}
}

func TestBarrierView_ClearView(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "view/")

	expect := []string{}
	ent := []*logical.StorageEntry{
		{Key: "foo", Value: []byte("test")},
		{Key: "zip", Value: []byte("test")},
		{Key: "foo/bar", Value: []byte("test")},
		{Key: "foo/zap", Value: []byte("test")},
		{Key: "foo/bar/baz", Value: []byte("test")},
		{Key: "foo/bar/zoo", Value: []byte("test")},
	}

	for _, e := range ent {
		expect = append(expect, e.Key)
		if err := view.Put(context.Background(), e); err != nil {
			t.Fatalf("err: %v", err)
		}
	}

	// Clear the keys
	if err := logical.ClearView(context.Background(), view); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Collect the keys
	out, err := logical.CollectKeys(context.Background(), view)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("have keys: %#v", out)
	}
}

func TestBarrierView_Readonly(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")

	// Add a key before enabling read-only
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	if err := view.Put(context.Background(), entry); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Enable read only mode
	view.SetReadOnlyErr(logical.ErrReadOnly)

	// Put should fail in readonly mode
	if err := view.Put(context.Background(), entry); err != logical.ErrReadOnly {
		t.Fatalf("err: %v", err)
	}

	// Delete nested
	if err := view.Delete(context.Background(), "test"); err != logical.ErrReadOnly {
		t.Fatalf("err: %v", err)
	}

	// Check the non-nested key
	e, err := view.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if e == nil {
		t.Fatal("key test missing")
	}
}

func TestBarrierView_Prefix(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")

	prefix := view.Prefix()
	if prefix != "foo/" {
		t.Fatalf("expected prefix 'foo/', got '%s'", prefix)
	}

	// Test SubView prefix
	subView := view.SubView("bar/")
	subPrefix := subView.Prefix()
	if subPrefix != "foo/bar/" {
		t.Fatalf("expected prefix 'foo/bar/', got '%s'", subPrefix)
	}
}

func TestBarrierView_PutNilEntry(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")

	// Putting a nil entry should return an error
	err := view.Put(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error when putting nil entry")
	}
	if err.Error() != "cannot write nil entry" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestBarrierView_ReadOnlyPropagation(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")

	// Set read-only error
	view.SetReadOnlyErr(logical.ErrReadOnly)

	// Create a sub-view
	subView := view.SubView("bar/")

	// Sub-view should also be read-only
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	err := subView.Put(context.Background(), entry)
	if err != logical.ErrReadOnly {
		t.Fatalf("expected ErrReadOnly, got: %v", err)
	}
}

func TestBarrierView_GetReadOnlyErr(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")

	// Initially should be nil
	err := view.GetReadOnlyErr()
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}

	// Set read-only error
	view.SetReadOnlyErr(logical.ErrReadOnly)

	// Should now return the error
	err = view.GetReadOnlyErr()
	if err != logical.ErrReadOnly {
		t.Fatalf("expected ErrReadOnly, got: %v", err)
	}

	// Clear the error
	view.SetReadOnlyErr(nil)

	// Should be nil again
	err = view.GetReadOnlyErr()
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestBarrierView_ListPage(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "view/")

	// Add some entries
	entries := []*logical.StorageEntry{
		{Key: "a", Value: []byte("test")},
		{Key: "b", Value: []byte("test")},
		{Key: "c", Value: []byte("test")},
		{Key: "d", Value: []byte("test")},
		{Key: "e", Value: []byte("test")},
	}

	for _, e := range entries {
		if err := view.Put(context.Background(), e); err != nil {
			t.Fatalf("err: %v", err)
		}
	}

	// Test ListPage with limit
	keys, err := view.ListPage(context.Background(), "", "", 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
}

func TestBarrierView_NestedSubViews(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	root := NewBarrierView(barrier, "root/")
	level1 := root.SubView("level1/")
	level2 := level1.SubView("level2/")

	// Put an entry in the deepest view
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	if err := level2.Put(context.Background(), entry); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify it's accessible from all levels
	out, err := barrier.Get(context.Background(), "root/level1/level2/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("missing nested key")
	}

	out, err = root.Get(context.Background(), "level1/level2/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("missing from root view")
	}

	out, err = level1.Get(context.Background(), "level2/test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("missing from level1 view")
	}

	out, err = level2.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("missing from level2 view")
	}

	// Verify prefix nesting
	if root.Prefix() != "root/" {
		t.Fatalf("expected 'root/', got '%s'", root.Prefix())
	}
	if level1.Prefix() != "root/level1/" {
		t.Fatalf("expected 'root/level1/', got '%s'", level1.Prefix())
	}
	if level2.Prefix() != "root/level1/level2/" {
		t.Fatalf("expected 'root/level1/level2/', got '%s'", level2.Prefix())
	}
}

func TestBarrierView_Isolation(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view1 := NewBarrierView(barrier, "view1/")
	view2 := NewBarrierView(barrier, "view2/")

	// Write to view1
	entry1 := &logical.StorageEntry{Key: "test", Value: []byte("view1")}
	if err := view1.Put(context.Background(), entry1); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Write to view2
	entry2 := &logical.StorageEntry{Key: "test", Value: []byte("view2")}
	if err := view2.Put(context.Background(), entry2); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Each view should only see its own data
	out1, err := view1.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out1 == nil || string(out1.Value) != "view1" {
		t.Fatalf("view1 data mismatch")
	}

	out2, err := view2.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out2 == nil || string(out2.Value) != "view2" {
		t.Fatalf("view2 data mismatch")
	}

	// Views should not see each other's data
	_, err = view1.Get(context.Background(), "../view2/test")
	if err == nil {
		t.Fatal("expected error accessing other view")
	}
}

func TestBarrierView_EmptyPrefix(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	// Create a view with empty prefix
	view := NewBarrierView(barrier, "")

	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	if err := view.Put(context.Background(), entry); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Should be able to retrieve it
	out, err := view.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("missing entry")
	}
}

func TestBarrierView_DeleteReadOnly(t *testing.T) {
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "foo/")

	// Add an entry
	entry := &logical.StorageEntry{Key: "test", Value: []byte("test")}
	if err := view.Put(context.Background(), entry); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Enable read-only mode
	view.SetReadOnlyErr(logical.ErrReadOnly)

	// Delete should fail
	err := view.Delete(context.Background(), "test")
	if err != logical.ErrReadOnly {
		t.Fatalf("expected ErrReadOnly, got: %v", err)
	}

	// Entry should still exist
	out, err := view.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out == nil {
		t.Fatal("entry should still exist")
	}
}
