package controlplane

import (
	"net/http"

	"gopkg.in/yaml.v3"
)

func (srv *Server) dumpConfig(w http.ResponseWriter, r *http.Request) {
	cfg := srv.currentConfig.Load()
	//w.Header().Set("Content-Type", "application/yaml")
	yaml.NewEncoder(w).Encode(cfg)
}
