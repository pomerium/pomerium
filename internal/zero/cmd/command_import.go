package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	"github.com/pomerium/pomerium/pkg/zero/cluster"
	"github.com/pomerium/pomerium/pkg/zero/importutil"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func BuildImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an existing configuration to a Zero cluster",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configFlag := cmd.InheritedFlags().Lookup("config")
			var configFile string
			if configFlag != nil {
				configFile = configFlag.Value.String()
			}
			envInfo := findEnvironmentInfo()
			if configFile == "" {
				configFile = envInfo.ConfigArg
			}
			if configFile == "" {
				return fmt.Errorf("no config file provided")
			}
			log.SetLevel(zerolog.ErrorLevel)
			src, err := config.NewFileOrEnvironmentSource(configFile, files.FullVersion())
			if err != nil {
				return err
			}
			cfg := src.GetConfig()

			client := zeroClientFromContext(cmd.Context())
			converted := cfg.Options.ToProto()
			for i, name := range importutil.GenerateRouteNames(converted.Routes) {
				converted.Routes[i].Name = name
			}
			var params cluster.ImportConfigurationParams
			if data, err := json.Marshal(envInfo); err == nil {
				hints := make(map[string]string)
				if err := json.Unmarshal(data, &hints); err == nil {
					pairs := []string{}
					for key, value := range hints {
						pairs = append(pairs, fmt.Sprintf("%s=%s", key, value))
					}
					if len(pairs) > 0 {
						params.XImportHints = &pairs
					}
				}
			}
			resp, err := client.ImportConfig(cmd.Context(), converted, &params)
			if err != nil {
				return fmt.Errorf("error importing config: %w", err)
			}
			if resp.Warnings != nil {
				for _, warn := range *resp.Warnings {
					cmd.Printf("warning: %s\n", warn)
				}
			}
			if resp.Messages != nil {
				for _, msg := range *resp.Messages {
					cmd.Printf("✔ %s\n", msg)
				}
			}
			cmd.Println("\nImport successful, return to your browser to continue setup.")
			return nil
		},
	}
	return cmd
}

type environmentInfo struct {
	SystemType          string `json:"systemType,omitempty"`
	Hostname            string `json:"hostname,omitempty"`
	KubernetesNamespace string `json:"kubernetesNamespace,omitempty"`
	Argv0               string `json:"argv0,omitempty"`
	ConfigArg           string `json:"configArg,omitempty"`
}

func findEnvironmentInfo() environmentInfo {
	var info environmentInfo
	if isKubernetes() {
		info.SystemType = "kubernetes"
		// search for downward api environment variables to see if we can determine
		// the current namespace (adds '-n <namespace>' to the command given in the
		// zero ui for users to copy/paste)
		for _, env := range []string{
			"POMERIUM_NAMESPACE", // the name we use in our official manifests
			"POD_NAMESPACE",      // very common alternative name
		} {
			if v, ok := os.LookupEnv(env); ok {
				info.KubernetesNamespace = v
				break
			}
		}
	} else if isDocker() {
		info.SystemType = "docker"
	} else {
		info.SystemType = "linux"
		info.Argv0 = os.Args[0]
		return info
	}
	info.Hostname, _ = os.Hostname()

	pid, ok := findPomeriumPid()
	if !ok {
		return info
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return info
	}
	args := bytes.Split(cmdline, []byte{0})
	if len(args) > 0 {
		info.Argv0 = string(args[0])
	}
	for i, arg := range args {
		if strings.Contains(string(arg), "-config") {
			if strings.Contains(string(arg), "-config=") {
				info.ConfigArg = strings.Split(string(arg), "=")[1]
			} else if len(args) > i+1 {
				info.ConfigArg = string(args[i+1])
			}
		}
	}
	return info
}

func isKubernetes() bool {
	return os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != ""
}

func isDocker() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func findPomeriumPid() (int, bool) {
	pid1Argv0 := getProcessArgv0(1)
	if path.Base(pid1Argv0) == "pomerium" {
		return 1, true
	}

	pidList, err := os.ReadFile("/proc/1/task/1/children")
	if err != nil {
		return 0, false
	}
	for _, pidStr := range strings.Fields(string(pidList)) {
		pid, _ := strconv.Atoi(pidStr)
		if path.Base(getProcessArgv0(pid)) == "pomerium" {
			return pid, true
		}
	}
	return 0, false
}

func getProcessArgv0(pid int) string {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	argv0, _, _ := bytes.Cut(cmdline, []byte{0})
	return string(argv0)
}
