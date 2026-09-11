package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"ipsets/internal/config"
	"ipsets/internal/firewall"
	"ipsets/internal/server"
	"ipsets/internal/store"
	"ipsets/internal/ui"

	"golang.org/x/term"
)

var version = "dev"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -r, --restore    Remove the IPSets nftables table and exit")
		fmt.Fprintln(os.Stderr, "  -p, --password   Reset the administrator password and exit")
		fmt.Fprintln(os.Stderr, "  -h, --help       Show this help message")
	}
	var restoreFirewall bool
	var resetPassword bool
	flag.BoolVar(&restoreFirewall, "r", false, "remove the IPSets nftables table and exit")
	flag.BoolVar(&restoreFirewall, "restore", false, "remove the IPSets nftables table and exit")
	flag.BoolVar(&resetPassword, "p", false, "reset the administrator password and exit")
	flag.BoolVar(&resetPassword, "password", false, "reset the administrator password and exit")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if cfg.InitialPassword != "" {
		log.Printf("created config at %s", cfg.ConfigPath)
		log.Printf("initial admin login: username=%s password=%s", cfg.AdminUsername, cfg.InitialPassword)
	}
	if resetPassword {
		password, err := newPassword()
		if err != nil {
			log.Fatal(err)
		}
		if err := config.ResetPassword(cfg.ConfigPath, password); err != nil {
			log.Fatal(err)
		}
		log.Printf("administrator password reset in %s", cfg.ConfigPath)
		return
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
	if restoreFirewall {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := wall.Restore(ctx); err != nil {
			log.Fatal(err)
		}
		if err := whitelist.UpdateFirewallState(store.FirewallState{Status: "restored", Message: "已通过 CLI 恢复原始状态"}); err != nil {
			log.Fatal(err)
		}
		log.Printf("removed nftables table inet %s", cfg.TableName)
		return
	}
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

func newPassword() (string, error) {
	if password := os.Getenv("IPSETS_NEW_PASSWORD"); password != "" {
		return password, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal; set IPSETS_NEW_PASSWORD for non-interactive reset")
	}
	fmt.Fprint(os.Stderr, "New password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	password := string(first)
	if strings.TrimSpace(password) == "" {
		return "", errors.New("password cannot be empty")
	}
	if password != string(second) {
		return "", errors.New("password confirmation does not match")
	}
	return password, nil
}
