package storage

import "context"

type Storage interface {
	Put(ctx context.Context, prefix string, key string, data map[string]any) error
	Get(ctx context.Context, prefix string, key string) (map[string]any, error)
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, prefix string, key string) error
	Init(ctx context.Context) error
	Stop() error
}
