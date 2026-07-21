package core

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func LoadJSONL(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows := []map[string]any{}
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 128*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line == "" {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		var row map[string]any
		if err := dec.Decode(&row); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		rows = append(rows, row)
	}
	return rows, scanner.Err()
}

func WriteJSONL(path string, rows []any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

func ReadTable(path string) ([]map[string]string, error) {
	suffix := strings.ToLower(filepath.Ext(path))
	if suffix == ".jsonl" {
		jrows, err := LoadJSONL(path)
		if err != nil {
			return nil, err
		}
		out := make([]map[string]string, 0, len(jrows))
		for _, row := range jrows {
			m := map[string]string{}
			for k, v := range row {
				m[k] = ToString(v)
			}
			out = append(out, m)
		}
		return out, nil
	}
	if suffix == ".json" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		var rows []map[string]any
		if err := dec.Decode(&rows); err != nil {
			var wrapper map[string][]map[string]any
			if err2 := json.Unmarshal(data, &wrapper); err2 != nil {
				return nil, err
			}
			rows = wrapper["rows"]
		}
		out := make([]map[string]string, 0, len(rows))
		for _, row := range rows {
			m := map[string]string{}
			for k, v := range row {
				m[k] = ToString(v)
			}
			out = append(out, m)
		}
		return out, nil
	}
	return ReadCSV(path)
}

func ReadCSV(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	header, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return []map[string]string{}, nil
		}
		return nil, err
	}
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\ufeff")
	}
	rows := []map[string]string{}
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		row := map[string]string{}
		for i, col := range header {
			if i < len(rec) {
				row[col] = rec[i]
			} else {
				row[col] = ""
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func WriteCSV(path string, rows []map[string]any, preferred []string) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	fields := OrderedFields(rows, preferred)
	if err := w.Write(fields); err != nil {
		return err
	}
	for _, row := range rows {
		rec := make([]string, len(fields))
		for i, field := range fields {
			v := row[field]
			switch x := v.(type) {
			case nil:
				rec[i] = ""
			case string:
				rec[i] = x
			case []string, []int, []float64, []any, map[string]any, map[string]int:
				b, _ := json.Marshal(x)
				rec[i] = string(b)
			default:
				rec[i] = fmt.Sprint(v)
			}
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

func OrderedFields(rows []map[string]any, preferred []string) []string {
	seen := map[string]bool{}
	fields := []string{}
	for _, f := range preferred {
		if f != "" && !seen[f] {
			seen[f] = true
			fields = append(fields, f)
		}
	}
	extras := []string{}
	for _, row := range rows {
		for k := range row {
			if !seen[k] {
				seen[k] = true
				extras = append(extras, k)
			}
		}
	}
	sort.Strings(extras)
	return append(fields, extras...)
}

func StringRowsToAny(rows []map[string]string) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		m := map[string]any{}
		for k, v := range row {
			m[k] = v
		}
		out = append(out, m)
	}
	return out
}
