// Package main is a deliberately flawed Go program used as a testdata fixture
// for go-analyzer. Each violation is annotated with the rule it triggers.
package main

import (
	"crypto/md5"  // want: SEC002
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand" // want: SEC006
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// UndocumentedExported is exported but has no godoc comment. // want: LINT001
func UndocumentedExported() {}

// neverCalled is an unexported function that is never called anywhere. // want: DEAD001
func neverCalled() {
	fmt.Println("I am dead code")
}

// RaceLoopCapture demonstrates a goroutine capturing a loop variable. // want: RACE001
func RaceLoopCapture() {
	values := []int{1, 2, 3}
	var wg sync.WaitGroup
	for _, v := range values {
		wg.Add(1)
		go func() { // want: RACE001
			defer wg.Done()
			fmt.Println(v) // v captured from outer scope
		}()
	}
	wg.Wait()
}

// RaceMapWrite demonstrates concurrent map writes without a mutex. // want: RACE002
func RaceMapWrite() {
	m := make(map[string]int)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) { // want: RACE002
			defer wg.Done()
			m[fmt.Sprintf("key%d", n)] = n // map write in goroutine without mutex
		}(i)
	}
	wg.Wait()
}

// RegexpInsideFunction compiles a regexp inside a function body. // want: PERF002
func RegexpInsideFunction(s string) bool {
	re := regexp.MustCompile(`^\d+$`) // want: PERF002
	return re.MatchString(s)
}

// StringConcatInLoop concatenates strings with + inside a loop. // want: PERF001
func StringConcatInLoop(items []string) string {
	result := ""
	for _, item := range items {
		result = result + item // want: PERF001
	}
	return result
}

// InsecureTLSConfig creates a TLS configuration with InsecureSkipVerify. // want: SEC001
func InsecureTLSConfig() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // want: SEC001
		},
	}
	return &http.Client{Transport: tr}
}

// WeakHash demonstrates use of the md5 package. // want: SEC002
func WeakHash(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// SQLInjection builds a SQL query with string concatenation. // want: SEC005
func SQLInjection(db *sql.DB, userID string) {
	query := "SELECT * FROM users WHERE id = " + userID // want: SEC005
	rows, err := db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()
}

// ExecWithVariable runs a command with a variable argument. // want: SEC003
func ExecWithVariable(cmd string) error {
	out := exec.Command(cmd) // want: SEC003
	return out.Run()
}

// InsecureRandom uses math/rand for generating "secure" tokens. // want: SEC006
func InsecureRandom() int {
	return rand.Intn(1000) // want: SEC006
}

// HighComplexityFunction has cyclomatic complexity > 10. // want: CMPLX001
func HighComplexityFunction(a, b, c, d, e, f int) string { // want: CMPLX004
	result := ""
	if a > 0 {
		result += "a"
	} else if a < 0 {
		result += "neg-a"
	}
	if b > 0 {
		result += "b"
	} else if b < 0 {
		result += "neg-b"
	}
	if c > 0 {
		result += "c"
	}
	if d > 0 && e > 0 {
		result += "de"
	} else if d < 0 || e < 0 {
		result += "neg-de"
	}
	switch f {
	case 1:
		result += "one"
	case 2:
		result += "two"
	case 3:
		result += "three"
	default:
		result += "other"
	}
	if strings.Contains(result, "a") && strings.Contains(result, "b") {
		result += "-ab"
	} else if strings.Contains(result, "c") {
		result += "-c"
	}
	return result
}

// DeadCodeAfterReturn has unreachable code after a return statement. // want: DEAD002
func DeadCodeAfterReturn() string {
	return "done"
	fmt.Println("this is unreachable") // want: DEAD002
	return "never"
}

// main is the entry point.
func main() {
	fmt.Println("sample: intentionally flawed Go program for go-analyzer testing")
}
