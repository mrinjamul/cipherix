package utils

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

const (
	minProgressSize = 10 * 1024 * 1024 // 10 MB — minimum file size to show bar
	progressBarWidth = 30
)

type ProgressBar struct {
	total, current int64
	label          string
	start          time.Time
	enabled        bool
	mu             sync.Mutex
}

func NewProgressBar(total int64, label string) *ProgressBar {
	enabled := term.IsTerminal(int(os.Stderr.Fd())) && total >= minProgressSize
	return &ProgressBar{
		total:   total,
		label:   label,
		start:   time.Now(),
		enabled: enabled,
	}
}

func (pb *ProgressBar) Add(n int64) {
	if !pb.enabled || n <= 0 {
		return
	}
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.current += n
	if pb.current > pb.total {
		pb.current = pb.total
	}
	pb.render()
}

func (pb *ProgressBar) render() {
	pct := float64(pb.current) / float64(pb.total) * 100
	filled := int(pct / 100 * float64(progressBarWidth))
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	bar := strings.Repeat("=", filled) + strings.Repeat("-", progressBarWidth-filled)
	cur := FormatBytes(pb.current)
	tot := FormatBytes(pb.total)
	fmt.Fprintf(os.Stderr, "\r %s [%s] %5.1f%% (%s / %s)", pb.label, bar, pct, cur, tot)
}

func (pb *ProgressBar) Done() {
	if !pb.enabled {
		return
	}
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.current = pb.total
	pb.render()
	fmt.Fprintln(os.Stderr)
}

type ProgressReader struct {
	r   io.Reader
	bar *ProgressBar
}

func NewProgressReader(r io.Reader, total int64, label string, forceDisable bool) *ProgressReader {
	bar := NewProgressBar(total, label)
	if forceDisable {
		bar.enabled = false
	}
	return &ProgressReader{r: r, bar: bar}
}

func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.bar.Add(int64(n))
	return n, err
}

func (pr *ProgressReader) Done() {
	pr.bar.Done()
}

func FormatBytes(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KiB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
