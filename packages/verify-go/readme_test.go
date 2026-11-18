package dbaverify

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestReadmeMatchesExamples keeps README.md's code samples identical to the tested Example
// functions in example_test.go (between "// README:begin <name>" and "// README:end").
func TestReadmeMatchesExamples(t *testing.T) {
	source, err := os.ReadFile("example_test.go")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?s)// README:begin (\w+)\n(.*?)\n\t// README:end`).FindAllStringSubmatch(string(source), -1)
	if len(blocks) == 0 {
		t.Fatal("no README blocks in example_test.go")
	}
	for _, block := range blocks {
		lines := strings.Split(block[2], "\n")
		for i, line := range lines {
			lines[i] = strings.TrimPrefix(line, "\t")
		}
		if sample := strings.Join(lines, "\n"); !strings.Contains(string(readme), "```go\n"+sample+"\n```") {
			t.Errorf("README.md does not contain the %q example verbatim:\n%s", block[1], sample)
		}
	}
}
