package common

import (
	"fmt"
	"net/http"
	"time"
)

// FormatSize formats a size in bytes to a human-readable string
func FormatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// FormatTime formats a time.Time to a string
func FormatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// IsPubliclyAccessible checks if a URL is publicly accessible
func IsPubliclyAccessible(url string) (bool, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 2xx status codes indicate public access
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}

	// 403 indicates the resource exists but is forbidden (restricted)
	if resp.StatusCode == 403 {
		return false, nil
	}

	// 404 could mean it doesn't exist or is private
	return false, nil
}
