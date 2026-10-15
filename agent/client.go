package main

// Kommunikation mit dem SIEM.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var errUnauthorized = errors.New("das SIEM kennt diesen Agenten nicht (mehr) – wurde er entfernt oder gesperrt?")

type Client struct {
	server string
	token  string
	http   *http.Client
}

func newClient(server, token string, insecure bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // bewusst per --insecure gewählt
	}
	tr.MaxIdleConnsPerHost = 4
	return &Client{
		server: strings.TrimRight(server, "/"),
		token:  token,
		http:   &http.Client{Transport: tr, Timeout: 60 * time.Second},
	}
}

type apiError struct {
	Status int
	Detail string
}

func (e *apiError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("SIEM antwortet mit %d: %s", e.Status, e.Detail)
	}
	return fmt.Sprintf("SIEM antwortet mit %d", e.Status)
}

func (c *Client) do(method, path string, body []byte, headers map[string]string, out any) error {
	req, err := http.NewRequest(method, c.server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mini-siem-agent/"+version)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return errUnauthorized
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(data, &e)
		return &apiError{Status: resp.StatusCode, Detail: e.Detail}
	}
	if out != nil {
		if b, ok := out.(*[]byte); ok {
			*b = data
			return nil
		}
		return json.Unmarshal(data, out)
	}
	return nil
}

type EnrollResponse struct {
	AgentID  int    `json:"agent_id"`
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
}

func (c *Client) Enroll(key string, info SystemInfo) (*EnrollResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"key": key, "machine_id": info.MachineID, "hostname": info.Hostname, "os": info.OS,
		"os_version": info.OSVersion, "arch": info.Arch, "version": version,
	})
	var out EnrollResponse
	err := c.do("POST", "/api/agent/enroll", body, nil, &out)
	return &out, err
}

type UpdateInfo struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`
}

type CheckinResponse struct {
	AgentID       int            `json:"agent_id"`
	Name          string         `json:"name"`
	Config        *CentralConfig `json:"config"`
	ConfigVersion string         `json:"config_version"`
	Update        *UpdateInfo    `json:"update"`
}

func (c *Client) Checkin(info SystemInfo, stats map[string]any) (*CheckinResponse, error) {
	body, _ := json.Marshal(map[string]any{
		"version": version, "hostname": info.Hostname, "os_version": info.OSVersion, "stats": stats,
	})
	var out CheckinResponse
	err := c.do("POST", "/api/agent/checkin", body, nil, &out)
	return &out, err
}

// SendEvents überträgt einen bereits mit gzip komprimierten JSON-Stapel.
func (c *Client) SendEvents(gz []byte) error {
	return c.do("POST", "/api/agent/events", gz, map[string]string{"Content-Encoding": "gzip"}, nil)
}

func (c *Client) Download(path string) ([]byte, error) {
	var out []byte
	err := c.do("GET", path, nil, nil, &out)
	return out, err
}
