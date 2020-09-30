package management

import "time"

type StatManager struct {
	*Management
}

func newStatManager(m *Management) *StatManager {
	return &StatManager{m}
}

// ActiveUsers retrieves the number of active users that logged in during the
// last 30 days.
//
// See: https://auth0.com/docs/api/management/v2#!/Stats/get_active_users
func (m *StatManager) ActiveUsers() (i int, err error) {
	err = m.get(m.uri("stats", "active-users"), &i)
	return
}

type DailyStat struct {
	Date            *time.Time `json:"date"`
	Logins          *int       `json:"logins"`
	Signups         *int       `json:"signups"`
	LeakedPasswords *int       `json:"leaked_passwords"`
	UpdatedAt       *time.Time `json:"updated_at"`
	CreatedAt       *time.Time `json:"created_at"`
}

// Daily retrieves the number of logins, signups and breached-password
// detections (subscription required) that occurred each day within a specified
// date range.
//
// See: https://auth0.com/docs/api/management/v2#!/Stats/get_daily
func (m *StatManager) Daily(opts ...ListOption) (ds []*DailyStat, err error) {
	err = m.get(m.uri("stats", "daily")+m.q(opts), &ds)
	return
}
