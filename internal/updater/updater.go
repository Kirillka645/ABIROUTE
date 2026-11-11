package updater

import (
	"abiroute/internal/config"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const latestReleaseAPI = "https://api.github.com/repos/Kirillka645/ABIROUTE/releases/latest"

type UpdateInfo struct {
	Available   bool   `json:"available"`
	CurrentVer  string `json:"currentVer"`
	LatestVer   string `json:"latestVer"`
	DownloadURL string `json:"downloadUrl"`
	ReleaseURL  string `json:"releaseUrl"`
	Notes       string `json:"notes"`
}

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(v)), "v")
	parts := strings.Split(v, ".")
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		out[i], _ = strconv.Atoi(parts[i])
	}
	return out
}

func isNewer(latest, current string) bool {
	l, c := parseSemver(latest), parseSemver(current)
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func CheckForUpdates(ctx context.Context) UpdateInfo {
	info := UpdateInfo{CurrentVer: config.AppVersion, LatestVer: config.AppVersion}
	cctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, latestReleaseAPI, nil)
	if err != nil {
		return info
	}
	req.Header.Set("User-Agent", "ABIRoute/"+config.AppVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return info
	}
	defer resp.Body.Close()

	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if json.NewDecoder(resp.Body).Decode(&rel) != nil || rel.TagName == "" {
		return info
	}

	info.LatestVer = strings.TrimPrefix(rel.TagName, "v")
	info.ReleaseURL = rel.HTMLURL
	info.Notes = rel.Body
	for _, a := range rel.Assets {
		if strings.EqualFold(a.Name, "ABIRoute.exe") {
			info.DownloadURL = a.URL
			break
		}
	}
	info.Available = isNewer(info.LatestVer, config.AppVersion) && info.DownloadURL != ""
	return info
}

// ApplySelfUpdate downloads the new ABIRoute.exe, renames the running executable to .old, and spawns the updated binary.
func ApplySelfUpdate(ctx context.Context, downloadURL string) error {
	if strings.TrimSpace(downloadURL) == "" {
		return fmt.Errorf("ссылка на обновление отсутствует")
	}
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	// Clean any leftover .old binary from previous update
	oldPath := exePath + ".old"
	_ = os.Remove(oldPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ABIRoute/"+config.AppVersion)
	cli := &http.Client{Timeout: 120 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("не удалось скачать обновление: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("сервер обновлений вернул HTTP %d", resp.StatusCode)
	}

	newTmp := exePath + ".new"
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
	if err != nil || len(raw) < 1_000_000 {
		return fmt.Errorf("скачанный файл обновления повреждён")
	}
	if err := os.WriteFile(newTmp, raw, 0o755); err != nil {
		return err
	}

	if err := os.Rename(exePath, oldPath); err != nil {
		_ = os.Remove(newTmp)
		return fmt.Errorf("не удалось заменить текущий файл: %w", err)
	}
	if err := os.Rename(newTmp, exePath); err != nil {
		_ = os.Rename(oldPath, exePath)
		return err
	}

	return exec.Command(exePath).Start()
}
