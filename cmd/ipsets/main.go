package main

import (
	"log"
	"net/http"

	"ipsets/internal/config"
	"ipsets/internal/firewall"
	"ipsets/internal/server"
	"ipsets/internal/store"
	"ipsets/internal/ui"
)

var version = "dev"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if cfg.InitialPassword != "" {
		log.Printf("created config at %s", cfg.ConfigPath)
		log.Printf("initial admin login: username=%s password=%s", cfg.AdminUsername, cfg.InitialPassword)
	}

	whitelist, err := store.Open(cfg.ConfigPath)
	if err != nil {
		log.Fatal(err)
	}
	wall := firewall.NewNFTManager(firewall.NFTConfig{
		TableName: cfg.TableName,
		TCPPorts:  cfg.ProtectedPorts,
		DataDir:   cfg.DataDir,
	})
	app := server.New(server.AppConfig{
		Config:  cfg,
		Store:   whitelist,
		Wall:    wall,
		Static:  ui.Handler(),
		Version: version,
	})

	log.Printf("ipsets listening on %s; protected TCP ports: %v", cfg.ListenAddr, cfg.ProtectedPorts)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, app))
}
