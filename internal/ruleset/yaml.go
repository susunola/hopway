package ruleset

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const maxGeneralYAMLSize = 2 << 20

// Large rule providers usually have a single block payload. Stream that
// form so the YAML decoder cannot materialize millions of syntax nodes.
// Small documents can still use the full decoder for aliases and flow syntax.
func (c *Content) parseYAML(ctx context.Context, behavior string, data []byte) error {
	reader := contextReader{ctx, bytes.NewReader(data)}
	if len(data) > maxGeneralYAMLSize {
		if !utf8.Valid(data) {
			return errors.New("rule-set YAML must be UTF-8")
		}
		return c.parseBlockPayload(ctx, behavior, reader)
	}
	var doc struct {
		Payload []string `yaml:"payload"`
	}
	if err := yaml.NewDecoder(reader).Decode(&doc); err != nil && err != io.EOF {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("rule-set YAML must contain a payload list")
	}
	for _, line := range doc.Payload {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.addLine(behavior, line); err != nil {
			return err
		}
	}
	return nil
}

func (c *Content) parseBlockPayload(ctx context.Context, behavior string, reader io.Reader) error {
	invalid := errors.New("YAML rule sets above 2 MB must use a single block payload of plain or simply quoted entries")
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	header := false
	indent := -1
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := scanner.Text()
		if strings.ContainsRune(raw, 0) {
			return invalid
		}
		line := strings.TrimLeft(raw, " ")
		columns := len(raw) - len(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !header {
			if columns != 0 || stripYAMLComment(strings.TrimPrefix(line, "\ufeff")) != "payload:" {
				return invalid
			}
			header = true
			continue
		}
		if indent == -1 {
			indent = columns
		}
		if columns != indent || !strings.HasPrefix(line, "- ") {
			return invalid
		}
		entry, ok := simpleYAMLEntry(strings.TrimSpace(line[2:]))
		if !ok {
			return invalid
		}
		if err := c.addLine(behavior, entry); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !header {
		return invalid
	}
	return nil
}

func stripYAMLComment(line string) string {
	for offset := 0; ; {
		i := strings.IndexByte(line[offset:], '#')
		if i == -1 {
			break
		}
		i += offset
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
			line = line[:i]
			break
		}
		offset = i + 1
	}
	return strings.TrimRight(line, " \t")
}

func simpleYAMLEntry(entry string) (string, bool) {
	if entry == "" {
		return "", true
	}
	switch entry[0] {
	case '\'', '"':
		end := strings.IndexByte(entry[1:], entry[0])
		if end < 0 {
			return "", false
		}
		suffix := entry[end+2:]
		if suffix != "" && (suffix[0] != ' ' && suffix[0] != '\t' || stripYAMLComment(strings.TrimLeft(suffix, " \t")) != "") {
			return "", false
		}
		value := entry[1 : end+1]
		return value, entry[0] != '"' || !strings.Contains(value, "\\")
	case '{', '}', '[', ']', ',', '|', '>', '!', '&', '*', '%', '@', '`':
		return "", false
	}
	entry = stripYAMLComment(entry)
	if strings.Contains(entry, ": ") || strings.Contains(entry, ":\t") || strings.HasSuffix(entry, ":") ||
		entry == "-" || entry == "?" || strings.HasPrefix(entry, "- ") || strings.HasPrefix(entry, "? ") {
		return "", false
	}
	switch entry {
	case "~", "null", "Null", "NULL":
		return "", true
	}
	return entry, true
}
