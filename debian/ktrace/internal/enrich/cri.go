package enrich

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type K8sIdentity struct {
	Namespace   string
	Pod         string
	Container   string
	PodUID      string
	ContainerID string
	Image       string
	Runtime     string
	Source      string // endpoint
}

type CRIResolver struct {
	endpoint string
	conn     *grpc.ClientConn
	client   runtimeapi.RuntimeServiceClient

	mu     sync.RWMutex
	cache  map[string]K8sIdentity
	neg    map[string]time.Time
	negTTL time.Duration
}

func NewCRIResolver(endpoints []string, timeout time.Duration) (*CRIResolver, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	var lastErr error
	for _, ep := range endpoints {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		conn, err := dialCRI(ep, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		c := runtimeapi.NewRuntimeServiceClient(conn)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, verr := c.Version(ctx, &runtimeapi.VersionRequest{})
		cancel()
		if verr != nil {
			_ = conn.Close()
			lastErr = verr
			continue
		}

		return &CRIResolver{
			endpoint: ep,
			conn:     conn,
			client:   c,
			cache:    make(map[string]K8sIdentity, 4096),
			neg:      make(map[string]time.Time, 4096),
			negTTL:   2 * time.Minute,
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no CRI endpoints provided")
	}
	return nil, fmt.Errorf("CRI unavailable: %w", lastErr)
}

func (r *CRIResolver) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

func (r *CRIResolver) ResolveContainer(containerID string) (K8sIdentity, bool) {
	if r == nil || containerID == "" || containerID == "-" {
		return K8sIdentity{}, false
	}
	// normalize
	containerID = strings.ToLower(strings.TrimSpace(containerID))

	r.mu.RLock()
	if v, ok := r.cache[containerID]; ok {
		r.mu.RUnlock()
		return v, true
	}
	if until, ok := r.neg[containerID]; ok && time.Now().Before(until) {
		r.mu.RUnlock()
		return K8sIdentity{}, false
	}
	r.mu.RUnlock()

	// Try exact first
	id, ident, ok := r.resolveExact(containerID)
	if ok {
		r.mu.Lock()
		r.cache[id] = ident
		// Also cache the original key if different (prefix)
		if id != containerID {
			r.cache[containerID] = ident
		}
		r.mu.Unlock()
		return ident, true
	}

	// fallback: prefix match via ListContainers
	fullID, err := r.findContainerByPrefix(containerID)
	if err == nil && fullID != "" {
		_, ident2, ok2 := r.resolveExact(fullID)
		if ok2 {
			r.mu.Lock()
			r.cache[fullID] = ident2
			r.cache[containerID] = ident2
			r.mu.Unlock()
			return ident2, true
		}
	}

	// negative cache
	r.mu.Lock()
	r.neg[containerID] = time.Now().Add(r.negTTL)
	r.mu.Unlock()
	return K8sIdentity{}, false
}

func (r *CRIResolver) resolveExact(containerID string) (string, K8sIdentity, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := r.client.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     false,
	})
	if err != nil || resp == nil || resp.Status == nil {
		return "", K8sIdentity{}, false
	}

	labels := resp.Status.Labels
	ns := "-"
	pod := "-"
	container := "-"
	podUID := "-"
	if labels != nil {
		if v := labels["io.kubernetes.pod.namespace"]; v != "" {
			ns = v
		}
		if v := labels["io.kubernetes.pod.name"]; v != "" {
			pod = v
		}
		if v := labels["io.kubernetes.container.name"]; v != "" {
			container = v
		}
		if v := labels["io.kubernetes.pod.uid"]; v != "" {
			podUID = v
		}
	}

	image := "-"
	if resp.Status.Image != nil && resp.Status.Image.Image != "" {
		image = resp.Status.Image.Image
	}

	runtime := "-"
	if resp.Status.RuntimeHandler != "" {
		runtime = resp.Status.RuntimeHandler
	}

	ident := K8sIdentity{
		Namespace:   ns,
		Pod:         pod,
		Container:   container,
		PodUID:      podUID,
		ContainerID: containerID,
		Image:       image,
		Runtime:     runtime,
		Source:      r.endpoint,
	}
	return containerID, ident, true
}

func (r *CRIResolver) findContainerByPrefix(prefix string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := r.client.ListContainers(ctx, &runtimeapi.ListContainersRequest{})
	if err != nil || resp == nil {
		return "", err
	}
	for _, c := range resp.Containers {
		if c == nil || c.Id == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(c.Id), prefix) {
			return c.Id, nil
		}
	}
	return "", errors.New("no container with prefix")
}

func dialCRI(endpoint string, timeout time.Duration) (*grpc.ClientConn, error) {
	ep := strings.TrimSpace(endpoint)
	if strings.HasPrefix(ep, "unix://") {
		ep = strings.TrimPrefix(ep, "unix://")
	}
	if ep == "" {
		return nil, errors.New("empty endpoint")
	}

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		d.Timeout = timeout
		return d.DialContext(ctx, "unix", addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return grpc.DialContext(
		ctx,
		ep,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithBlock(),
	)
}
