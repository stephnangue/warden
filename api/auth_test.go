package api

import (
	"context"
	"errors"
	"testing"
)

type mockAuthMethod struct {
	resource *Resource
	err      error
}

func (m *mockAuthMethod) Login(ctx context.Context, client *Client) (*Resource, error) {
	return m.resource, m.err
}

func TestAuth_Login(t *testing.T) {
	config := DefaultConfig()
	client, _ := NewClient(config)

	t.Run("nil auth method", func(t *testing.T) {
		_, err := client.Auth().Login(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil auth method")
		}
	})

	t.Run("successful login", func(t *testing.T) {
		mock := &mockAuthMethod{
			resource: &Resource{Data: map[string]interface{}{"token": "abc"}},
		}
		r, err := client.Auth().Login(context.Background(), mock)
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if r == nil {
			t.Fatal("expected resource")
		}
		if r.Data["token"] != "abc" {
			t.Errorf("unexpected token: %v", r.Data["token"])
		}
	})

	t.Run("login error", func(t *testing.T) {
		mock := &mockAuthMethod{
			err: errors.New("auth failed"),
		}
		_, err := client.Auth().Login(context.Background(), mock)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
