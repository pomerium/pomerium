package management

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"time"
)

type Job struct {
	// The job's identifier. Useful to retrieve its status
	ID *string `json:"id,omitempty"`
	// The job's status
	Status *string `json:"status,omitempty"`
	// The type of job
	Type *string `json:"type,omitempty"`
	// The date when the job was created.
	CreatedAt *time.Time `json:"created_at,omitempty"`

	// The user_id of the user to whom the email will be sent
	UserID *string `json:"user_id,omitempty"`
	// The id of the client, if not provided the global one will be used
	ClientID *string `json:"cliend_id,omitempty"`

	// The id of the connection.
	ConnectionID *string `json:"connection_id,omitempty"`
	// The url to download the result of the job.
	Location *string `json:"location,omitempty"`
	// The percentage of the work done so far.
	PercentageDone *int `json:"percentage_done,omitempty"`
	// Estimated amount of time remaining to finish the job.
	TimeLeftSeconds *int `json:"time_left_seconds,omitempty"`
	// The format of the file. Valid values are: "json" and "csv".
	Format *string `json:"format,omitempty"`
	// Limit the number of records.
	Limit *int `json:"limit,omitempty"`
	// A list of fields to be included in the CSV. If omitted, a set of
	// predefined fields will be exported.
	Fields []map[string]interface{} `json:"fields,omitempty"`

	// A list of users. Used when importing users in bulk.
	Users []map[string]interface{} `json:"users,omitempty"`
	// If false, users will only be inserted. If there are already user(s) with
	// the same emails as one or more of those being inserted, they will fail.
	// If this value is set to true and the user being imported already exists,
	// the user will be updated with the new information.
	Upsert *bool `json:"upsert,omitempty"`
	// Optional user defined string that can be used for correlating multiple
	// jobs, and is returned as part of the job status response.
	ExternalID *string `json:"external_id,omitempty"`
	// When true, sends a completion email to all tenant owners when the job is
	// finished. The default is true, so you must explicitly set this parameter
	// to false if you do not want emails sent.
	SendCompletionEmail *bool `json:"send_completion_email,omitempty"`
}

type JobManager struct {
	*Management
}

func newJobManager(m *Management) *JobManager {
	return &JobManager{m}
}

func (m *JobManager) VerifyEmail(j *Job) error {
	return m.post(m.uri("jobs", "verification-email"), j)
}

// Retrieves a job. Useful to check its status.
//
// See: https://auth0.com/docs/api/management/v2#!/Jobs/get_jobs_by_id
func (m *JobManager) Read(id string) (*Job, error) {
	j := new(Job)
	err := m.get(m.uri("jobs", id), j)
	return j, err
}

// Export all users to a file via a long-running job.
//
// See: https://auth0.com/docs/api/management/v2#!/Jobs/post_users_exports
func (m *JobManager) ExportUsers(j *Job) error {
	return m.post(m.uri("jobs", "users-exports"), j)
}

// Import users from a formatted file into a connection via a long-running job.
//
// See: https://auth0.com/docs/api/management/v2#!/Jobs/post_users_imports
func (m *JobManager) ImportUsers(j *Job) error {

	var payload bytes.Buffer
	mp := multipart.NewWriter(&payload)

	if j.ConnectionID != nil {
		mp.WriteField("connection_id", *j.ConnectionID)
	}
	if j.Upsert != nil {
		mp.WriteField("upsert", strconv.FormatBool(*j.Upsert))
	}
	if j.ExternalID != nil {
		mp.WriteField("external_id", *j.ExternalID)
	}
	if j.SendCompletionEmail != nil {
		mp.WriteField("send_completion_email", strconv.FormatBool(*j.SendCompletionEmail))
	}
	if j.Users != nil {
		b, err := json.Marshal(j.Users)
		if err != nil {
			return err
		}
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="users"; filename="users.json"`)
		h.Set("Content-Type", "application/json")
		w, err := mp.CreatePart(h)
		if err != nil {
			return err
		}
		w.Write(b)
	}
	mp.Close()

	req, err := http.NewRequest("POST", m.uri("jobs", "users-imports"), &payload)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", mp.FormDataContentType())

	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()

	if m.http == nil {
		m.http = http.DefaultClient
	}

	res, err := m.http.Do(req.WithContext(ctx))
	if err != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return err
		}
	}

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		return newError(res.Body)
	}

	if res.StatusCode != http.StatusNoContent {
		defer res.Body.Close()
		return json.NewDecoder(res.Body).Decode(j)
	}

	return nil
}
