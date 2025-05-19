//go:build linux
// +build linux

package main

import (
	"strings"
	"testing"
)

func TestGetContainerRuntime(t *testing.T) {
	runtime := getContainerRuntime()
	if runtime == "" {
		t.Error("expected a runtime string, got empty string")
	}
}

func TestHasNamespace(t *testing.T) {
	_, err := hasNamespace("pid")
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			t.Skip("skipping: requires root to read /proc/1/ns/pid")
		}
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetUserNamespaceInfo(t *testing.T) {
	_, mappings := getUserNamespaceInfo()
	if len(mappings) == 0 {
		t.Error("expected mappings to be >= 0")
	}
}

func TestGetAppArmorProfile(t *testing.T) {
	profile := getAppArmorProfile()
	if profile == "" {
		t.Error("expected a profile string, got empty string")
	}
	if profile == "unavailable" {
		t.Skip("AppArmor not available on this system (common in WSL or non-AppArmor distros)")
	}
}

func TestGetCapabilities(t *testing.T) {
	_, err := getCapabilities()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetSeccompEnforcingMode(t *testing.T) {
	mode := getSeccompEnforcingMode()
	if mode == "" {
		t.Error("expected a mode string, got empty string")
	}
}
