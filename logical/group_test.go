package logical

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testGroup() *Group {
	return &Group{
		ID:          "id-1",
		Name:        "deployers",
		Type:        GroupTypeVirtual,
		Description: "CI deployers",
		Roles:       []string{"deploy", "read"},
		Selectors: []Selector{
			{"mount": {"auth/jwt/"}, "repo": {"acme/*"}},
			{"mount": {"auth/k8s/"}, "workload": {"a", "b"}},
		},
		MaxAge:   10 * time.Minute,
		Metadata: map[string]string{"owner": "platform"},
	}
}

func TestParseGroupType(t *testing.T) {
	for _, s := range []string{"virtual", "internal", "directory"} {
		gt, err := ParseGroupType(s)
		require.NoError(t, err)
		assert.Equal(t, GroupType(s), gt)
	}
	for _, s := range []string{"", "selector", "Virtual", "external"} {
		_, err := ParseGroupType(s)
		assert.Error(t, err, s)
	}
}

func TestGroup_CloneIsDeep(t *testing.T) {
	g := testGroup()
	c := g.Clone()
	require.Equal(t, g, c)

	c.Roles[0] = "x"
	c.Selectors[0]["repo"][0] = "x"
	c.Selectors[1]["new"] = []string{"y"}
	c.Metadata["owner"] = "x"
	assert.Equal(t, "deploy", g.Roles[0])
	assert.Equal(t, "acme/*", g.Selectors[0]["repo"][0])
	assert.NotContains(t, g.Selectors[1], "new")
	assert.Equal(t, "platform", g.Metadata["owner"])

	assert.Equal(t, len(c.Roles), cap(c.Roles), "no spare capacity")
	assert.Equal(t, len(c.Selectors[1]["workload"]), cap(c.Selectors[1]["workload"]))
	assert.Nil(t, (*Group)(nil).Clone())
}

func TestGroup_Hash(t *testing.T) {
	base := testGroup().Hash()

	same := testGroup()
	same.ID, same.CreatedAt, same.UpdatedAt = "other-id", time.Now(), time.Now()
	assert.Equal(t, base, same.Hash(), "ID and timestamps are not content")

	for name, mutate := range map[string]func(*Group){
		"name":        func(g *Group) { g.Name = "x" },
		"type":        func(g *Group) { g.Type = GroupTypeInternal },
		"description": func(g *Group) { g.Description = "x" },
		"roles":       func(g *Group) { g.Roles = []string{"deploy"} },
		"selector":    func(g *Group) { g.Selectors[0]["repo"] = []string{"acme/x"} },
		"rule order":  func(g *Group) { g.Selectors[0], g.Selectors[1] = g.Selectors[1], g.Selectors[0] },
		"max_age":     func(g *Group) { g.MaxAge = time.Minute },
		"metadata":    func(g *Group) { g.Metadata["owner"] = "x" },
		"split value": func(g *Group) { g.Selectors[1]["workload"] = []string{"ab"} },
	} {
		g := testGroup()
		mutate(g)
		assert.NotEqual(t, base, g.Hash(), name)
	}
	assert.Equal(t, "group:deployers", GroupLabel("deployers"))
}

func TestAdmission_Membership(t *testing.T) {
	var nilAdm *Admission
	assert.Nil(t, nilAdm.LoadMembership())
	assert.False(t, nilAdm.CompareAndSwapMembership(nil, &Membership{}))

	adm := &Admission{}
	assert.Nil(t, adm.LoadMembership())
	m1 := &Membership{Gen: 1}
	assert.True(t, adm.CompareAndSwapMembership(nil, m1))
	assert.Same(t, m1, adm.LoadMembership())
	assert.False(t, adm.CompareAndSwapMembership(nil, &Membership{Gen: 2}), "a stale old value loses")
	assert.Same(t, m1, adm.LoadMembership())
	assert.Zero(t, testing.AllocsPerRun(100, func() { _ = adm.LoadMembership() }))
}
