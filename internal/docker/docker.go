// Package docker is a minimal read-only client for the Docker Engine API.
// It uses only GET endpoints.
package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client talks to the Docker daemon over its Unix socket.
type Client struct {
	hc     *http.Client // requests with a timeout
	stream *http.Client // the events stream, which never ends
}

// New returns a client for the socket at path.
func New(path string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
		MaxIdleConns: 4,
	}
	return &Client{
		hc:     &http.Client{Transport: tr, Timeout: 15 * time.Second},
		stream: &http.Client{Transport: tr},
	}
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{resp.StatusCode, fmt.Sprintf("docker GET %s: %s: %s", path, resp.Status, b)}
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// StatusError is a non-200 answer from Docker.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return e.Msg }

// Endpoint is a container's attachment to one network.
type Endpoint struct {
	NetworkID           string
	MacAddress          string
	IPAddress           string
	GlobalIPv6Address   string
	GlobalIPv6PrefixLen int
	Gateway             string
	IPv6Gateway         string
}

// Container is the part of a container's inspect output that dfw reads.
type Container struct {
	ID    string `json:"Id"`
	Name  string
	State struct {
		Running   bool
		Pid       int
		StartedAt string
	}
	Config struct {
		Labels map[string]string
	}
	HostConfig struct {
		Privileged bool
		DNS        []string `json:"Dns"`
	}
	NetworkSettings struct {
		Networks map[string]Endpoint
	}
}

// Summary is one entry of the container list.
type Summary struct {
	ID string `json:"Id"`
}

// Network is the part of a network's inspect output that dfw reads.
type Network struct {
	ID      string `json:"Id"`
	Name    string
	Driver  string
	Options map[string]string
}

// Version is Docker's version information.
type Version struct {
	Version string
}

// Running lists the IDs of running containers attached to any of networks.
func (c *Client) Running(ctx context.Context, networks []string) ([]string, error) {
	f, _ := json.Marshal(map[string][]string{"network": networks})
	var s []Summary
	if err := c.get(ctx, "/containers/json?filters="+url.QueryEscape(string(f)), &s); err != nil {
		return nil, err
	}
	ids := make([]string, len(s))
	for i, x := range s {
		ids[i] = x.ID
	}
	return ids, nil
}

// Inspect returns a container's details.
func (c *Client) Inspect(ctx context.Context, id string) (*Container, error) {
	var ct Container
	return &ct, c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &ct)
}

// Networks lists all networks.
func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	var ns []Network
	return ns, c.get(ctx, "/networks", &ns)
}

// Version returns Docker's version.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	return v, c.get(ctx, "/version", &v)
}

// Event is one message from the events stream.
type Event struct {
	Type   string
	Action string
	Actor  struct{ ID string }
}

// Events streams container start, die and rename events and network
// connect, disconnect, create and destroy events into ch until the stream ends or ctx is cancelled. It returns once the
// stream is open, and closes ch when the stream ends.
func (c *Client) Events(ctx context.Context, ch chan<- Event) error {
	f := `{"type":["container","network"],"event":["start","die","rename","connect","disconnect","create","destroy"]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/events?filters="+url.QueryEscape(f), nil)
	if err != nil {
		return err
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		return fmt.Errorf("docker events: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("docker events: %s", resp.Status)
	}
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		dec := json.NewDecoder(bufio.NewReader(resp.Body))
		for {
			var e Event
			if err := dec.Decode(&e); err != nil {
				return
			}
			select {
			case ch <- e:
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}
