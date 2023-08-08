package reconciler

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var unmarshalOpts = protodelim.UnmarshalOptions{}

// ReadBundleRecords reads records in a protobuf wire format from src.
// Each record is expected to be a databroker.Record.
func ReadBundleRecords(src io.Reader) (RecordSetBundle[DatabrokerRecord], error) {
	// start reading

	r := bufio.NewReader(src)
	rsb := make(RecordSetBundle[DatabrokerRecord])
	for {
		record := new(databroker.Record)
		err := unmarshalOpts.UnmarshalFrom(r, record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading protobuf record: %w", err)
		}

		data, err := protojson.Marshal(record)
		if err == nil {
			fmt.Printf("record: %s\n", string(data))
		}

		rsb.Add(DatabrokerRecord{record})
	}

	return rsb, nil
}
