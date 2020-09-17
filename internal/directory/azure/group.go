package azure

import "sort"

type stringSet map[string]struct{}

func newStringSet() stringSet {
	return make(stringSet)
}

func (ss stringSet) add(value string) {
	ss[value] = struct{}{}
}

func (ss stringSet) has(value string) bool {
	if ss == nil {
		return false
	}

	_, ok := ss[value]
	return ok
}

func (ss stringSet) sorted() []string {
	if ss == nil {
		return nil
	}

	s := make([]string, 0, len(ss))
	for v := range ss {
		s = append(s, v)
	}
	sort.Strings(s)
	return s
}

type stringSetSet map[string]stringSet

func newStringSetSet() stringSetSet {
	return make(stringSetSet)
}

func (sss stringSetSet) add(v1, v2 string) {
	ss, ok := sss[v1]
	if !ok {
		ss = newStringSet()
		sss[v1] = ss
	}
	ss.add(v2)
}

func (sss stringSetSet) get(v1 string) stringSet {
	return sss[v1]
}

type groupLookup struct {
	childUserIDToParentGroupID  stringSetSet
	childGroupIDToParentGroupID stringSetSet
}

func newGroupLookup() *groupLookup {
	return &groupLookup{
		childUserIDToParentGroupID:  newStringSetSet(),
		childGroupIDToParentGroupID: newStringSetSet(),
	}
}

func (l *groupLookup) addGroup(parentGroupID string, childGroupIDs, childUserIDs []string) {
	for _, childGroupID := range childGroupIDs {
		l.childGroupIDToParentGroupID.add(childGroupID, parentGroupID)
	}
	for _, childUserID := range childUserIDs {
		l.childUserIDToParentGroupID.add(childUserID, parentGroupID)
	}
}

func (l *groupLookup) getUserIDs() []string {
	s := make([]string, 0, len(l.childUserIDToParentGroupID))
	for userID := range l.childUserIDToParentGroupID {
		s = append(s, userID)
	}
	sort.Strings(s)
	return s
}

func (l *groupLookup) getGroupIDsForUser(userID string) []string {
	groupIDs := newStringSet()
	var todo []string
	for groupID := range l.childUserIDToParentGroupID.get(userID) {
		todo = append(todo, groupID)
	}

	for len(todo) > 0 {
		groupID := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if groupIDs.has(groupID) {
			continue
		}

		groupIDs.add(groupID)
		for parentGroupID := range l.childGroupIDToParentGroupID.get(groupID) {
			todo = append(todo, parentGroupID)
		}
	}

	return groupIDs.sorted()
}
