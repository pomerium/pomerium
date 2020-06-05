package manager

import (
	"strings"
	"time"
)

type job interface {
	Key() string
	Due() time.Time
}

type refreshSessionJob struct {
	Session
}

func (job refreshSessionJob) Key() string {
	return strings.Join([]string{
		job.UserId,
		job.Id,
	}, "\037")
}

func (job refreshSessionJob) Due() time.Time {
	return job.NextRefresh()
}

type refreshUserJob struct {
	User
}

func (job refreshUserJob) Key() string {
	return job.User.Id
}

func (job refreshUserJob) Due() time.Time {
	return job.NextRefresh()
}
