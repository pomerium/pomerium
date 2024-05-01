package manager

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestDataStore(t *testing.T) {
	t.Parallel()

	ds := newDataStore()
	s, u := ds.getSessionAndUser("S1")
	assert.Nil(t, s, "should return a nil session when none exists")
	assert.Nil(t, u, "should return a nil user when none exists")

	u, ss := ds.getUserAndSessions("U1")
	assert.Nil(t, u, "should return a nil user when none exists")
	assert.Empty(t, ss, "should return an empty list of sessions when no user exists")

	s = &session.Session{Id: "S1", UserId: "U1"}
	ds.putSession(s)
	s1, u1 := ds.getSessionAndUser("S1")
	assert.NotNil(t, s1, "should return a non-nil session")
	assert.NotSame(t, s, s1, "should return different pointers")
	assert.Empty(t, cmp.Diff(s, s1, protocmp.Transform()), "should be the same as was entered")
	assert.Nil(t, u1, "should return a nil user when only the session exists")

	ds.putUser(&user.User{
		Id: "U1",
	})
	_, u1 = ds.getSessionAndUser("S1")
	assert.NotNil(t, u1, "should return a user now that it has been added")

	ds.putSession(&session.Session{Id: "S4", UserId: "U1"})
	ds.putSession(&session.Session{Id: "S3", UserId: "U1"})
	ds.putSession(&session.Session{Id: "S2", UserId: "U1"})
	u, ss = ds.getUserAndSessions("U1")
	assert.NotNil(t, u)
	assert.Empty(t, cmp.Diff(ss, []*session.Session{
		{Id: "S1", UserId: "U1"},
		{Id: "S2", UserId: "U1"},
		{Id: "S3", UserId: "U1"},
		{Id: "S4", UserId: "U1"},
	}, protocmp.Transform()), "should return all sessions in id order")

	ds.deleteSession("S4")

	u, ss = ds.getUserAndSessions("U1")
	assert.NotNil(t, u)
	assert.Empty(t, cmp.Diff(ss, []*session.Session{
		{Id: "S1", UserId: "U1"},
		{Id: "S2", UserId: "U1"},
		{Id: "S3", UserId: "U1"},
	}, protocmp.Transform()), "should return all sessions in id order")

	ds.deleteUser("U1")
	u, ss = ds.getUserAndSessions("U1")
	assert.Nil(t, u)
	assert.Empty(t, cmp.Diff(ss, []*session.Session{
		{Id: "S1", UserId: "U1"},
		{Id: "S2", UserId: "U1"},
		{Id: "S3", UserId: "U1"},
	}, protocmp.Transform()), "should still return all sessions in id order")

	ds.deleteSession("S1")
	ds.deleteSession("S2")
	ds.deleteSession("S3")

	u, ss = ds.getUserAndSessions("U1")
	assert.Nil(t, u)
	assert.Empty(t, ss)
}
