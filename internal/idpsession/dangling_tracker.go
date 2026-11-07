package idpsession

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/go-set/v3"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/protoutil"
	slicesutil "github.com/pomerium/pomerium/pkg/slices"
)

// recordID is (type_url, id).
type recordID [2]string

type danglingTracker struct {
	q        ChangeQueue
	typeURLs *set.Set[string]
	now      func() time.Time

	records  *set.Set[recordID]
	bindings *set.Set[recordID]
}

func newDanglingTracker(q ChangeQueue, now func() time.Time, typeURLs []string) DanglingTracker {
	toCheck := set.New[string](10)
	for _, typeURL := range typeURLs {
		if typeURL == protoutil.GetTypeURL(new(idpsession.Binding)) {
			panic("cannot register type.googleapis.com/idpsession.Binding to dangling tracker")
		}
		toCheck.Insert(typeURL)
	}

	return &danglingTracker{
		q:        q,
		now:      now,
		typeURLs: toCheck,
		records:  set.New[recordID](10),
		bindings: set.New[recordID](10),
	}
}

func (d *danglingTracker) UpdateBindings(_ context.Context, bind *idpsession.Binding) {
	d.bindings.Insert([2]string{bind.GetTypeUrl(), bind.GetId()})
}

func (d *danglingTracker) CheckRecord(_ context.Context, rec *databroker.Record) {
	recTypeURL := rec.GetData().GetTypeUrl()
	if !d.typeURLs.Contains(recTypeURL) {
		return
	}
	d.records.Insert([2]string{rec.GetData().GetTypeUrl(), rec.GetId()})
}

func (d *danglingTracker) ScheduleDangling(ctx context.Context) {
	bindingsWithoutRecords, recordsWithoutBindings := slicesutil.Difference(
		slices.Collect(d.bindings.Items()),
		slices.Collect(d.records.Items()),
	)

	changes := make([]ChangeSet, 0, len(bindingsWithoutRecords)+len(recordsWithoutBindings))
	at := d.now()
	for _, recordID := range bindingsWithoutRecords {
		changes = append(changes, ChangeSet{
			At:            at,
			RecordID:      recordID[1],
			RecordTypeURL: bindingTypeURL,
			changeType:    changeDelete,
		})
	}
	for _, recordID := range recordsWithoutBindings {
		changes = append(changes, ChangeSet{
			At:            at,
			RecordID:      recordID[1],
			RecordTypeURL: recordID[0],
			changeType:    changeDelete,
		})
	}
	d.q.Schedule(ctx, changes...)
}

func (d *danglingTracker) Clear(_ context.Context) {
	d.bindings = set.New[recordID](10)
	d.records = set.New[recordID](10)
}
