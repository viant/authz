package api

import (
	"encoding/json"
	"github.com/viant/authz"
	"github.com/viant/xdatly/response"
	"testing"
)

func TestPublicErrorPreservesStatusForMCP(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
	}{{403, "forbidden"}, {401, "unauthorized"}, {503, "unavailable"}, {409, "conflict"}} {
		err := failure(tc.status, "safe message", authz.ErrDenied).(*response.Error)
		raw, e := json.Marshal(err.Payload)
		if e != nil {
			t.Fatal(e)
		}
		var body struct {
			Status  int
			Code    string
			Message string
		}
		if e = json.Unmarshal(raw, &body); e != nil {
			t.Fatal(e)
		}
		if body.Status != tc.status || body.Code != tc.code || body.Message != "safe message" {
			t.Fatalf("lost transport error metadata: %s", raw)
		}
	}
}
