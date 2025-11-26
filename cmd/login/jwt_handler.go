package login

import (
	"context"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/api/auth/jwt"
)

type JWTHandler struct{}

func (h JWTHandler) Auth(ctx context.Context, c *api.Client, m map[string]string) (*api.Resource, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = jwt.DefaultMountPath
	}
	role := m["role"]
	token := m["token"]

	var auth *jwt.JWTAuth
	auth, err := jwt.New(role, 
		jwt.WithToken(token),
		jwt.WithMount(mount),
	)
	if err != nil {
		return nil, err
	}

	result, err := auth.Login(ctx, c)
	if err != nil {
		return nil, err
	}

	return result, nil
}

