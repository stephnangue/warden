package core

// nsIndex is one namespace's groups, compiled and indexed, and its entities:
// what resolveRoleGrant and discovery load, one pointer per request.
// Immutable once published: a write builds a new one.
//
// The mount index serves compute. A virtual rule always names the mounts it
// trusts, so only the groups with a rule naming the admission's mount can
// match it. byMount holds every exact mount value; mountGlobs every mount
// pattern ("**" included). compute looks the admission's mount up in the map,
// tries each pattern, and evaluates only the groups found. The index only
// narrows: a group found is matched rule by rule in full, "mount" included, so
// a group whose one rule lists the mount and whose other rule does not is
// still decided by its rules.
type nsIndex struct {
	// gen is the store's publish counter at this publish. A membership computed
	// from another generation is recomputed.
	gen uint64

	// groupsByName are every group of the namespace, by name.
	groupsByName map[string]*groupEntry

	// selectors is the number of selectors across every rule of every virtual
	// group, "mount" included: what a worst-case recompute evaluates.
	selectors int

	// virtualGroups are the virtual groups, sorted by name: the only ones
	// compute matches by rule.
	virtualGroups []*groupEntry

	// byMount maps an exact mount value to the indexes into virtualGroups of the
	// groups that name it, ascending and without repeats.
	byMount map[string][]int32

	// mountGlobs are the groups' mount patterns, each with the index into
	// virtualGroups of the group that names it, in ascending group order.
	mountGlobs []mountGlob

	// entities are every entity of the namespace, in any state, and the
	// native identities they claim. They share the namespace value, and so its
	// generation, with the groups: an entity write publishes a new value under
	// the next generation, so every membership computed before it is
	// recomputed on its next request. Never nil once published (emptyEntities
	// when there are none).
	entities *nsEntities
}

// identitySnapshot is one published state of every namespace's identity
// index, keyed by namespace ID (the ID tokens carry). Immutable once
// published.
type identitySnapshot struct {
	byNS map[string]*nsIndex
}

// emptyIdentitySnapshot is what an unloaded store serves.
var emptyIdentitySnapshot = &identitySnapshot{}

// emptyNSIndex is what a snapshot answers for a namespace with neither groups
// nor entities: generation 0 and nothing to match. The store's generation
// counter starts above 0, so a membership computed against it is told apart
// from one computed against a published namespace, and stays valid exactly
// while the namespace has nothing.
var emptyNSIndex = &nsIndex{groupsByName: map[string]*groupEntry{}, entities: emptyEntities}

// namespace returns the index of namespace nsID, or emptyNSIndex when it has
// nothing. It takes no lock and does not allocate.
func (s *identitySnapshot) namespace(nsID string) *nsIndex {
	if g := s.byNS[nsID]; g != nil {
		return g
	}
	return emptyNSIndex
}

// withNamespace returns a snapshot in which namespace nsID holds g, or nothing
// when g is nil. s is left as it was; other namespaces are shared by pointer.
func (s *identitySnapshot) withNamespace(nsID string, g *nsIndex) *identitySnapshot {
	byNS := make(map[string]*nsIndex, len(s.byNS)+1)
	for k, v := range s.byNS {
		byNS[k] = v
	}
	if g != nil {
		byNS[nsID] = g
	} else {
		delete(byNS, nsID)
	}
	return &identitySnapshot{byNS: byNS}
}

// buildNSIndex builds a namespace's index at generation gen from its groups
// byName, taking ownership of the map, and its entities ents (nil is none).
// It returns nil for a namespace with neither groups nor entities, which the
// snapshot then serves as emptyNSIndex.
func buildNSIndex(byName map[string]*groupEntry, ents *nsEntities, gen uint64) *nsIndex {
	if ents == nil {
		ents = emptyEntities
	}
	if len(byName) == 0 && ents.count() == 0 {
		return nil
	}
	g := &nsIndex{gen: gen, groupsByName: byName, entities: ents}
	g.indexGroups()
	return g
}
