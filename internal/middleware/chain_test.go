package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// A constructor for middleware
// that writes its own "tag" into the RW and does nothing else.
// Useful in checking if a chain is behaving in the right order.
func tagMiddleware(tag string) Constructor {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(tag))
			h.ServeHTTP(w, r)
		})
	}
}

// Not recommended (https://golang.org/pkg/reflect/#Value.Pointer),
// but the best we can do.
func funcsEqual(f1, f2 interface{}) bool {
	val1 := reflect.ValueOf(f1)
	val2 := reflect.ValueOf(f2)
	return val1.Pointer() == val2.Pointer()
}

var testApp = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("app\n"))
})

func TestNew(t *testing.T) {
	c1 := func(h http.Handler) http.Handler {
		return nil
	}

	c2 := func(h http.Handler) http.Handler {
		return http.StripPrefix("potato", nil)
	}

	slice := []Constructor{c1, c2}

	chain := NewChain(slice...)
	for k := range slice {
		if !funcsEqual(chain.constructors[k], slice[k]) {
			t.Error("New does not add constructors correctly")
		}
	}
}

func TestThenWorksWithNoMiddleware(t *testing.T) {
	if !funcsEqual(NewChain().Then(testApp), testApp) {
		t.Error("Then does not work with no middleware")
	}
}

func TestThenTreatsNilAsDefaultServeMux(t *testing.T) {
	if NewChain().Then(nil) != http.DefaultServeMux {
		t.Error("Then does not treat nil as DefaultServeMux")
	}
}

func TestThenFuncTreatsNilAsDefaultServeMux(t *testing.T) {
	if NewChain().ThenFunc(nil) != http.DefaultServeMux {
		t.Error("ThenFunc does not treat nil as DefaultServeMux")
	}
}

func TestThenFuncConstructsHandlerFunc(t *testing.T) {
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	chained := NewChain().ThenFunc(fn)
	rec := httptest.NewRecorder()

	chained.ServeHTTP(rec, (*http.Request)(nil))

	if reflect.TypeOf(chained) != reflect.TypeOf(http.HandlerFunc(nil)) {
		t.Error("ThenFunc does not construct HandlerFunc")
	}
}

func TestThenOrdersHandlersCorrectly(t *testing.T) {
	t1 := tagMiddleware("t1\n")
	t2 := tagMiddleware("t2\n")
	t3 := tagMiddleware("t3\n")

	chained := NewChain(t1, t2, t3).Then(testApp)

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chained.ServeHTTP(w, r)

	if w.Body.String() != "t1\nt2\nt3\napp\n" {
		t.Error("Then does not order handlers correctly")
	}
}

func TestAppendAddsHandlersCorrectly(t *testing.T) {
	chain := NewChain(tagMiddleware("t1\n"), tagMiddleware("t2\n"))
	newChain := chain.Append(tagMiddleware("t3\n"), tagMiddleware("t4\n"))

	if len(chain.constructors) != 2 {
		t.Error("chain should have 2 constructors")
	}
	if len(newChain.constructors) != 4 {
		t.Error("newChain should have 4 constructors")
	}

	chained := newChain.Then(testApp)

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chained.ServeHTTP(w, r)

	if w.Body.String() != "t1\nt2\nt3\nt4\napp\n" {
		t.Error("Append does not add handlers correctly")
	}
}

func TestAppendRespectsImmutability(t *testing.T) {
	chain := NewChain(tagMiddleware(""))
	newChain := chain.Append(tagMiddleware(""))

	if &chain.constructors[0] == &newChain.constructors[0] {
		t.Error("Apppend does not respect immutability")
	}
}

func TestExtendAddsHandlersCorrectly(t *testing.T) {
	chain1 := NewChain(tagMiddleware("t1\n"), tagMiddleware("t2\n"))
	chain2 := NewChain(tagMiddleware("t3\n"), tagMiddleware("t4\n"))
	newChain := chain1.Extend(chain2)

	if len(chain1.constructors) != 2 {
		t.Error("chain1 should contain 2 constructors")
	}
	if len(chain2.constructors) != 2 {
		t.Error("chain2 should contain 2 constructors")
	}
	if len(newChain.constructors) != 4 {
		t.Error("newChain should contain 4 constructors")
	}

	chained := newChain.Then(testApp)

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	chained.ServeHTTP(w, r)

	if w.Body.String() != "t1\nt2\nt3\nt4\napp\n" {
		t.Error("Extend does not add handlers in correctly")
	}
}

func TestExtendRespectsImmutability(t *testing.T) {
	chain := NewChain(tagMiddleware(""))
	newChain := chain.Extend(NewChain(tagMiddleware("")))

	if &chain.constructors[0] == &newChain.constructors[0] {
		t.Error("Extend does not respect immutability")
	}
}
