package tripper

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockTransport struct {
	id string
}

func (t *mockTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()

	w.WriteString(t.id)
	return w.Result(), nil
}

// mockMiddleware appends the id into the response body as
// the call stack unwinds.
//
// If your chain is c1->c2->t, it should return 't,c2,c1'
func mockMiddleware(id string) func(next http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			resp, _ := next.RoundTrip(r)

			body, _ := io.ReadAll(resp.Body)
			mockResp := httptest.NewRecorder()
			mockResp.Write(body)
			mockResp.WriteString(fmt.Sprintf(",%s", id))
			return mockResp.Result(), nil
		})
	}
}

func TestNew(t *testing.T) {
	m1 := mockMiddleware("c1")
	m2 := mockMiddleware("c2")
	t1 := &mockTransport{id: "t"}
	want := "t,c2,c1"

	chain := NewChain(m1, m2)

	resp, _ := chain.Then(t1).
		RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

	if len(chain.constructors) != 2 {
		t.Errorf("Wrong number of constructors in chain")
	}

	b, _ := io.ReadAll(resp.Body)
	if string(b) != want {
		t.Errorf("Wrong constructors.  want=%s, got=%s", want, b)
	}
}

func TestThenNoMiddleware(t *testing.T) {
	chain := NewChain()
	t1 := &mockTransport{id: "t"}
	want := "t"

	resp, _ := chain.Then(t1).
		RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

	b, _ := io.ReadAll(resp.Body)
	if string(b) != want {
		t.Errorf("Wrong constructors.  want=%s, got=%s", want, b)
	}
}

func TestNilThen(t *testing.T) {
	if NewChain().Then(nil) != http.DefaultTransport {
		t.Error("Then does not treat nil as DefaultTransport")
	}
}

func TestAppend(t *testing.T) {
	chain := NewChain(mockMiddleware("c1"))
	if len(chain.constructors) != 1 {
		t.Errorf("Wrong number of constructors in chain")
	}

	chain = chain.Append(mockMiddleware("c2"))
	t1 := &mockTransport{id: "t"}
	want := "t,c2,c1"

	resp, _ := chain.Then(t1).
		RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

	if len(chain.constructors) != 2 {
		t.Errorf("Wrong number of constructors in chain")
	}

	b, _ := io.ReadAll(resp.Body)
	if string(b) != want {
		t.Errorf("Wrong constructors.  want=%s, got=%s", want, b)
	}
}

func TestAppendImmutability(t *testing.T) {
	chain := NewChain(mockMiddleware("c1"))
	chain.Append(mockMiddleware("c2"))
	t1 := &mockTransport{id: "t"}
	want := "t,c1"

	if len(chain.constructors) != 1 {
		t.Errorf("Append does not respect immutability")
	}

	resp, _ := chain.Then(t1).
		RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

	b, _ := io.ReadAll(resp.Body)
	if string(b) != want {
		t.Errorf("Wrong constructors.  want=%s, got=%s", want, b)
	}
}
