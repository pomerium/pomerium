package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-jsonnet"
	"github.com/rs/zerolog/log"

	"github.com/pomerium/pomerium/integration/internal/netutil"
)

var requiredDeployments = []string{
	"ingress-nginx/nginx-ingress-controller",
	"default/httpdetails",
	"default/openid",
	"default/pomerium-authenticate",
	"default/pomerium-authorize",
	"default/pomerium-proxy",
}

// Setup configures the test cluster so that it is ready for the integration tests.
func (cluster *Cluster) Setup(ctx context.Context) error {
	err := run(ctx, "kubectl", withArgs("cluster-info"))
	if err != nil {
		return fmt.Errorf("error running kubectl cluster-info: %w", err)
	}

	cluster.certs, err = bootstrapCerts(ctx)
	if err != nil {
		return err
	}

	jsonsrc, err := cluster.generateManifests()
	if err != nil {
		return err
	}

	err = applyManifests(ctx, jsonsrc)
	if err != nil {
		return err
	}

	hostport, err := cluster.getNodeHTTPSAddr(ctx)
	if err != nil {
		return err
	}

	cluster.Transport = &http.Transport{
		DialContext: netutil.NewLocalDialer((&net.Dialer{}), map[string]string{
			"443": hostport,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return nil
}

func (cluster *Cluster) getNodeHTTPSAddr(ctx context.Context) (hostport string, err error) {
	var buf bytes.Buffer

	args := []string{"get", "service", "--namespace", "ingress-nginx", "--output", "json",
		"ingress-nginx-nodeport"}
	err = run(ctx, "kubectl", withArgs(args...), withStdout(&buf))
	if err != nil {
		return "", fmt.Errorf("error getting service details with kubectl: %w", err)
	}

	var svcResult struct {
		Spec struct {
			Ports []struct {
				Name     string `json:"name"`
				NodePort int    `json:"nodePort"`
			} `json:"ports"`
			Selector map[string]string `json:"selector"`
		} `json:"spec"`
	}
	err = json.Unmarshal(buf.Bytes(), &svcResult)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling service details from kubectl: %w", err)
	}

	buf.Reset()

	args = []string{"get", "pods", "--namespace", "ingress-nginx", "--output", "json"}
	var sel []string
	for k, v := range svcResult.Spec.Selector {
		sel = append(sel, k+"="+v)
	}
	args = append(args, "--selector", strings.Join(sel, ","))
	err = run(ctx, "kubectl", withArgs(args...), withStdout(&buf))
	if err != nil {
		return "", fmt.Errorf("error getting pod details with kubectl: %w", err)
	}

	var podsResult struct {
		Items []struct {
			Status struct {
				HostIP string `json:"hostIP"`
			} `json:"status"`
		} `json:"items"`
	}
	err = json.Unmarshal(buf.Bytes(), &podsResult)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling pod details from kubectl (json=%s): %w", buf.String(), err)
	}

	var port string
	for _, p := range svcResult.Spec.Ports {
		if p.Name == "https" {
			port = strconv.Itoa(p.NodePort)
		}
	}
	if port == "" {
		return "", fmt.Errorf("failed to find https port in kubectl service results (result=%v)", svcResult)
	}

	var hostIP string
	for _, item := range podsResult.Items {
		hostIP = item.Status.HostIP
	}
	if hostIP == "" {
		return "", fmt.Errorf("failed to find host ip in kubectl pod results: %w", err)
	}

	return net.JoinHostPort(hostIP, port), nil
}

func (cluster *Cluster) generateManifests() (string, error) {
	src, err := ioutil.ReadFile(filepath.Join(cluster.workingDir, "manifests", "manifests.jsonnet"))
	if err != nil {
		return "", fmt.Errorf("error reading manifest jsonnet src: %w", err)
	}

	vm := jsonnet.MakeVM()
	vm.ExtVar("tls-ca", cluster.certs.CA)
	vm.ExtVar("tls-cert", cluster.certs.Cert)
	vm.ExtVar("tls-key", cluster.certs.Key)
	vm.Importer(&jsonnet.FileImporter{
		JPaths: []string{filepath.Join(cluster.workingDir, "manifests")},
	})
	jsonsrc, err := vm.EvaluateSnippet("manifests.jsonnet", string(src))
	if err != nil {
		return "", fmt.Errorf("error evaluating jsonnet (filename=manifests.jsonnet): %w", err)
	}

	return jsonsrc, nil
}

func applyManifests(ctx context.Context, jsonsrc string) error {
	err := run(ctx, "kubectl", withArgs("apply", "-f", "-"), withStdin(strings.NewReader(jsonsrc)))
	if err != nil {
		return fmt.Errorf("error applying manifests: %w", err)
	}

	log.Info().Msg("waiting for deployments to come up")
	ctx, clearTimeout := context.WithTimeout(ctx, 5*time.Minute)
	defer clearTimeout()
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	for {
		var buf bytes.Buffer
		err = run(ctx, "kubectl", withArgs("get", "deployments", "--all-namespaces", "--output", "json"),
			withStdout(&buf))
		if err != nil {
			return fmt.Errorf("error polling for deployment status: %w", err)
		}

		var results struct {
			Items []struct {
				Metadata struct {
					Namespace string `json:"namespace"`
					Name      string `json:"name"`
				} `json:"metadata"`
				Status struct {
					AvailableReplicas int `json:"availableReplicas"`
				} `json:"status"`
			} `json:"items"`
		}
		err = json.Unmarshal(buf.Bytes(), &results)
		if err != nil {
			return fmt.Errorf("error unmarshaling kubectl results: %w", err)
		}

		byName := map[string]int{}
		for _, item := range results.Items {
			byName[item.Metadata.Namespace+"/"+item.Metadata.Name] = item.Status.AvailableReplicas
		}

		done := true
		for _, dep := range requiredDeployments {
			if byName[dep] < 1 {
				done = false
				log.Warn().Str("deployment", dep).Msg("deployment is not ready yet")
			}
		}
		if done {
			break
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
		<-ticker.C
	}
	log.Info().Msg("all deployments are ready")

	return nil
}
