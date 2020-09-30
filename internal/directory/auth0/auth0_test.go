package auth0

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pomerium/pomerium/internal/directory/auth0/mock_auth0"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/stretchr/testify/assert"
	"gopkg.in/auth0.v4/management"
)

type mockNewRoleManagerFunc struct {
	CalledWithDomain         string
	CalledWithServiceAccount *ServiceAccount
	CalledWithContext        context.Context

	ReturnRoleManager RoleManager
	ReturnError       error
}

func (m *mockNewRoleManagerFunc) f(domain string, serviceAccount *ServiceAccount, ctx context.Context) (RoleManager, error) {
	m.CalledWithDomain = domain
	m.CalledWithServiceAccount = serviceAccount
	m.CalledWithContext = ctx

	return m.ReturnRoleManager, m.ReturnError
}

type listOptionMatcher struct {
	expected management.ListOption
}

func buildValues(opt management.ListOption) map[string][]string {
	v := url.Values{}
	opt(v)

	return v
}

func (lom listOptionMatcher) Matches(actual interface{}) bool {
	return gomock.Eq(buildValues(lom.expected)).Matches(buildValues(actual.(management.ListOption)))
}

func (lom listOptionMatcher) String() string {
	return fmt.Sprintf("is equal to %v", buildValues(lom.expected))
}

func stringPtr(in string) *string {
	return &in
}

func TestProvider_UserGroups(t *testing.T) {
	expectedDomain := "example.com"
	expectedServiceAccount := &ServiceAccount{ClientID: "c_id", Secret: "secret"}

	tests := []struct {
		name                         string
		setupRoleManagerExpectations func(*mock_auth0.MockRoleManager)
		newRoleManagerError          error
		expectedGroups               []*directory.Group
		expectedUsers                []*directory.User
		expectedError                error
	}{
		{
			name:                "errors if getting the role manager errors",
			newRoleManagerError: errors.New("new role manager error"),
			expectedError:       errors.New("auth0: could not get the role manager: new role manager error"),
		},
		{
			name: "errors if listing roles errors",
			setupRoleManagerExpectations: func(mrm *mock_auth0.MockRoleManager) {
				mrm.EXPECT().List(
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(nil, errors.New("list error"))
			},
			expectedError: errors.New("auth0: could not list roles: list error"),
		},
		{
			name: "errors if getting user ids errors",
			setupRoleManagerExpectations: func(mrm *mock_auth0.MockRoleManager) {
				mrm.EXPECT().List(
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.RoleList{
					Roles: []*management.Role{
						{
							ID:   stringPtr("i-am-role-id"),
							Name: stringPtr("i-am-role-name"),
						},
					},
				}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(nil, errors.New("users error"))
			},
			expectedError: errors.New("auth0: could not get users for role \"i-am-role-id\": users error"),
		},
		{
			name: "handles multiple pages of roles",
			setupRoleManagerExpectations: func(mrm *mock_auth0.MockRoleManager) {
				mrm.EXPECT().List(
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.RoleList{
					List: management.List{
						Total: 3,
						Start: 0,
						Limit: 1,
					},
					Roles: []*management.Role{
						{
							ID:   stringPtr("i-am-role-id-1"),
							Name: stringPtr("i-am-role-name-1"),
						},
					},
				}, nil)

				mrm.EXPECT().List(
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(1)},
				).Return(&management.RoleList{
					List: management.List{
						Total: 3,
						Start: 1,
						Limit: 1,
					},
					Roles: []*management.Role{
						{
							ID:   stringPtr("i-am-role-id-2"),
							Name: stringPtr("i-am-role-name-2"),
						},
					},
				}, nil)

				mrm.EXPECT().List(
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(2)},
				).Return(&management.RoleList{
					List: management.List{
						Total: 3,
						Start: 2,
						Limit: 1,
					},
					Roles: []*management.Role{
						{
							ID:   stringPtr("i-am-role-id-3"),
							Name: stringPtr("i-am-role-name-3"),
						},
					},
				}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id-1",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.UserList{}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id-2",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.UserList{}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id-3",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.UserList{}, nil)

			},
			expectedGroups: []*directory.Group{
				{
					Id:   "i-am-role-id-1",
					Name: "i-am-role-name-1",
				},
				{
					Id:   "i-am-role-id-2",
					Name: "i-am-role-name-2",
				},
				{
					Id:   "i-am-role-id-3",
					Name: "i-am-role-name-3",
				},
			},
		},
		{
			name: "handles multiple pages of users",
			setupRoleManagerExpectations: func(mrm *mock_auth0.MockRoleManager) {
				mrm.EXPECT().List(
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.RoleList{
					Roles: []*management.Role{
						{
							ID:   stringPtr("i-am-role-id-1"),
							Name: stringPtr("i-am-role-name-1"),
						},
					},
				}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id-1",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.UserList{
					List: management.List{
						Total: 3,
						Start: 0,
						Limit: 1,
					},
					Users: []*management.User{
						{ID: stringPtr("i-am-user-id-1")},
					},
				}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id-1",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(1)},
				).Return(&management.UserList{
					List: management.List{
						Total: 3,
						Start: 1,
						Limit: 1,
					},
					Users: []*management.User{
						{ID: stringPtr("i-am-user-id-2")},
					},
				}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id-1",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(2)},
				).Return(&management.UserList{
					List: management.List{
						Total: 3,
						Start: 2,
						Limit: 1,
					},
					Users: []*management.User{
						{ID: stringPtr("i-am-user-id-3")},
					},
				}, nil)

			},
			expectedGroups: []*directory.Group{
				{
					Id:   "i-am-role-id-1",
					Name: "i-am-role-name-1",
				},
			},
			expectedUsers: []*directory.User{
				{
					Id:       "auth0/i-am-user-id-1",
					GroupIds: []string{"i-am-role-id-1"},
				},
				{
					Id:       "auth0/i-am-user-id-2",
					GroupIds: []string{"i-am-role-id-1"},
				},
				{
					Id:       "auth0/i-am-user-id-3",
					GroupIds: []string{"i-am-role-id-1"},
				},
			},
		},
		{
			name: "correctly builds out groups and users",
			setupRoleManagerExpectations: func(mrm *mock_auth0.MockRoleManager) {
				mrm.EXPECT().List(
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.RoleList{
					List: management.List{
						Total: 2,
						Start: 0,
						Limit: 1,
					},
					Roles: []*management.Role{
						{
							ID:   stringPtr("i-am-role-id-1"),
							Name: stringPtr("i-am-role-name-1"),
						},
					},
				}, nil)

				mrm.EXPECT().List(
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(1)},
				).Return(&management.RoleList{
					List: management.List{
						Total: 2,
						Start: 1,
						Limit: 1,
					},
					Roles: []*management.Role{
						{
							ID:   stringPtr("i-am-role-id-2"),
							Name: stringPtr("i-am-role-name-2"),
						},
					},
				}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id-1",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.UserList{
					Users: []*management.User{
						{ID: stringPtr("i-am-user-id-4")},
						{ID: stringPtr("i-am-user-id-3")},
						{ID: stringPtr("i-am-user-id-2")},
						{ID: stringPtr("i-am-user-id-1")},
					},
				}, nil)

				mrm.EXPECT().Users(
					"i-am-role-id-2",
					listOptionMatcher{expected: management.IncludeTotals(true)},
					listOptionMatcher{expected: management.Page(0)},
				).Return(&management.UserList{
					Users: []*management.User{
						{ID: stringPtr("i-am-user-id-1")},
						{ID: stringPtr("i-am-user-id-4")},
						{ID: stringPtr("i-am-user-id-5")},
					},
				}, nil)
			},
			expectedGroups: []*directory.Group{
				{
					Id:   "i-am-role-id-1",
					Name: "i-am-role-name-1",
				},
				{
					Id:   "i-am-role-id-2",
					Name: "i-am-role-name-2",
				},
			},
			expectedUsers: []*directory.User{
				{
					Id:       "auth0/i-am-user-id-1",
					GroupIds: []string{"i-am-role-id-1", "i-am-role-id-2"},
				},
				{
					Id:       "auth0/i-am-user-id-2",
					GroupIds: []string{"i-am-role-id-1"},
				},
				{
					Id:       "auth0/i-am-user-id-3",
					GroupIds: []string{"i-am-role-id-1"},
				},
				{
					Id:       "auth0/i-am-user-id-4",
					GroupIds: []string{"i-am-role-id-1", "i-am-role-id-2"},
				},
				{
					Id:       "auth0/i-am-user-id-5",
					GroupIds: []string{"i-am-role-id-2"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mRoleManager := mock_auth0.NewMockRoleManager(ctrl)

			mNewRoleManagerFunc := mockNewRoleManagerFunc{
				ReturnRoleManager: mRoleManager,
				ReturnError:       tc.newRoleManagerError,
			}

			if tc.setupRoleManagerExpectations != nil {
				tc.setupRoleManagerExpectations(mRoleManager)
			}

			p := New(
				WithDomain(expectedDomain),
				WithServiceAccount(expectedServiceAccount),
			)
			p.cfg.newRoleManager = mNewRoleManagerFunc.f

			actualGroups, actualUsers, err := p.UserGroups(context.Background())
			if tc.expectedError != nil {
				assert.EqualError(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedGroups, actualGroups)
			assert.Equal(t, tc.expectedUsers, actualUsers)

			assert.Equal(t, expectedDomain, mNewRoleManagerFunc.CalledWithDomain)
			assert.Equal(t, expectedServiceAccount, mNewRoleManagerFunc.CalledWithServiceAccount)
		})
	}

}

func TestParseServiceAccount(t *testing.T) {
	tests := []struct {
		name                   string
		rawServiceAccount      string
		expectedServiceAccount *ServiceAccount
		expectedError          error
	}{
		{"valid", "eyJjbGllbnRfaWQiOiJpLWFtLWNsaWVudC1pZCIsInNlY3JldCI6ImktYW0tc2VjcmV0In0K",
			&ServiceAccount{
				ClientID: "i-am-client-id",
				Secret:   "i-am-secret",
			},
			nil,
		},
		{"base64 err", "!!!!", nil, errors.New("auth0: could not decode base64: illegal base64 data at input byte 0")},
		{"json err", "PAo=", nil, errors.New("auth0: could not unmarshal json: invalid character '<' looking for beginning of value")},
		{"no client_id", "eyJzZWNyZXQiOiJpLWFtLXNlY3JldCJ9Cg==", nil, errors.New("auth0: client_id is required")},
		{"no secret", "eyJjbGllbnRfaWQiOiJpLWFtLWNsaWVudC1pZCJ9Cg==", nil, errors.New("auth0: secret is required")},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actualServiceAccount, err := ParseServiceAccount(tc.rawServiceAccount)
			if tc.expectedError != nil {
				assert.EqualError(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedServiceAccount, actualServiceAccount)
		})
	}
}
