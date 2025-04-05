package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Finding struct {
	Module		string			`json:"module"`
	Target		string			`json:"target"`
	Type		string			`json:"type"`
	Description	string			`json:"description"`
	Severity	string			`json:"severity"`
	Data		map[string]interface{}	`json:"data"`
}

type JSONOutput struct {
	Timestamp	string		`json:"timestamp"`
	Target		string		`json:"target"`
	Findings	[]Finding	`json:"findings"`
}

type OutputWriter interface {
	Write(findings []Finding) error
	Close() error
}

type JSONWriter struct {
	file *os.File
}

func NewJSONWriter(filename string) (*JSONWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	return &JSONWriter{
		file: file,
	}, nil
}

func (w *JSONWriter) Write(findings []Finding) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}

	_, err = w.file.Write(data)
	return err
}

func (w *JSONWriter) Close() error {
	return w.file.Close()
}

type CSVWriter struct {
	writer	*csv.Writer
	file	*os.File
}

func NewCSVWriter(filename string) (*CSVWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	writer := csv.NewWriter(file)

	header := []string{"Type", "Target", "Module", "Description", "Severity", "Data"}
	if err := writer.Write(header); err != nil {
		file.Close()
		return nil, err
	}

	return &CSVWriter{
		writer:	writer,
		file:	file,
	}, nil
}

func (w *CSVWriter) Write(findings []Finding) error {
	for _, finding := range findings {
		record := []string{
			finding.Type,
			finding.Target,
			finding.Module,
			finding.Description,
			finding.Severity,
			fmt.Sprintf("%v", finding.Data),
		}
		if err := w.writer.Write(record); err != nil {
			return err
		}
	}
	w.writer.Flush()
	return w.writer.Error()
}

func (w *CSVWriter) Close() error {
	w.writer.Flush()
	return w.file.Close()
}

type MarkdownWriter struct {
	file *os.File
}

func NewMarkdownWriter(filename string) (*MarkdownWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	return &MarkdownWriter{file: file}, nil
}

func (w *MarkdownWriter) Write(findings []Finding) error {
	for _, finding := range findings {
		_, err := fmt.Fprintf(w.file, "## %s Finding\n\n", finding.Type)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w.file, "**Target:** %s  \n", finding.Target)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w.file, "**Module:** %s  \n", finding.Module)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w.file, "**Description:** %s  \n", finding.Description)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w.file, "**Severity:** %s  \n\n", finding.Severity)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w.file, "### Data\n\n")
		if err != nil {
			return err
		}

		for key, value := range finding.Data {
			_, err = fmt.Fprintf(w.file, "- **%s:** %v\n", key, value)
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprintf(w.file, "\n---\n\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *MarkdownWriter) Close() error {
	return w.file.Close()
}

type ConsoleWriter struct {
	writer io.Writer
}

func NewConsoleWriter(w io.Writer) *ConsoleWriter {
	return &ConsoleWriter{writer: w}
}

func (w *ConsoleWriter) Write(findings []Finding) error {
	for _, finding := range findings {
		_, err := fmt.Fprintln(w.writer, finding.String())
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *ConsoleWriter) Close() error {
	return nil
}

func GetWriter(format, outputFile string) (OutputWriter, error) {
	switch strings.ToLower(format) {
	case "json":
		return NewJSONWriter(outputFile)
	case "csv":
		return NewCSVWriter(outputFile)
	case "markdown", "md":
		return NewMarkdownWriter(outputFile)
	case "console":
		return NewConsoleWriter(os.Stdout), nil
	default:
		return NewConsoleWriter(os.Stdout), nil
	}
}

func NewFinding(module, target, findingType, description, severity string, data map[string]interface{}) Finding {
	return Finding{
		Module:		module,
		Target:		target,
		Type:		findingType,
		Description:	description,
		Severity:	severity,
		Data:		data,
	}
}

func SaveFindings(findings []Finding, filePath string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	format := "txt"
	if strings.HasSuffix(filePath, ".json") {
		format = "json"
	} else if strings.HasSuffix(filePath, ".csv") {
		format = "csv"
	} else if strings.HasSuffix(filePath, ".md") {
		format = "markdown"
	}

	writer, err := GetWriter(format, filePath)
	if err != nil {
		return err
	}
	defer writer.Close()

	return writer.Write(findings)
}

func SaveFindingsJSON(findings []Finding, filePath string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	output := JSONOutput{
		Timestamp:	time.Now().UTC().Format(time.RFC3339),
		Target:		findings[0].Target,
		Findings:	findings,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %v", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("writing JSON file: %v", err)
	}

	return nil
}

func (f Finding) String() string {
	switch f.Module {
	case "http":
		url := f.Data["url"].(string)
		status := f.Data["status_code"].(float64)
		techs := "[]"
		if technologies, ok := f.Data["technologies"].([]interface{}); ok {
			techStrings := make([]string, len(technologies))
			for i, t := range technologies {
				techStrings[i] = t.(string)
			}
			techs = fmt.Sprintf("[%s]", strings.Join(techStrings, ","))
		}
		size := f.Data["response_size"].(float64)
		return fmt.Sprintf("[%s] %s [%d] %s Size:%d", f.Severity, url, int(status), techs, int(size))
	default:
		return fmt.Sprintf("[%s] %s: %s", f.Severity, f.Type, f.Description)
	}
}

func (f Finding) JSON() string {
	b, _ := json.Marshal(f)
	return string(b)
}
