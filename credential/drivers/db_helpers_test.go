package drivers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultPortForEngine(t *testing.T) {
	assert.Equal(t, "5432", defaultPortForEngine("postgres"))
	assert.Equal(t, "3306", defaultPortForEngine("mysql"))
	assert.Equal(t, "1433", defaultPortForEngine("sqlserver"))
	assert.Equal(t, "5432", defaultPortForEngine(""))
	assert.Equal(t, "5432", defaultPortForEngine("unknown"))
}
