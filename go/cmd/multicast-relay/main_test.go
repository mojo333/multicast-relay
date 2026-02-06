package main

import (
	"os"
	"testing"
)

func TestFormatArgsMasksAESKey(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "no aes flag",
			args:     []string{"cmd", "--interfaces", "eth0", "eth1"},
			expected: "--interfaces eth0 eth1",
		},
		{
			name:     "aes with separate value",
			args:     []string{"cmd", "--interfaces", "eth0", "--aes", "mysecret", "--verbose"},
			expected: "--interfaces eth0 --aes **** --verbose",
		},
		{
			name:     "aes with equals",
			args:     []string{"cmd", "--aes=mysecret", "--interfaces", "eth0"},
			expected: "--aes=**** --interfaces eth0",
		},
		{
			name:     "single dash aes",
			args:     []string{"cmd", "-aes", "secret123"},
			expected: "-aes ****",
		},
		{
			name:     "single dash aes with equals",
			args:     []string{"cmd", "-aes=secret123"},
			expected: "-aes=****",
		},
		{
			name:     "no args",
			args:     []string{"cmd"},
			expected: "",
		},
		{
			name:     "aes at end",
			args:     []string{"cmd", "--interfaces", "eth0", "--aes", "key"},
			expected: "--interfaces eth0 --aes ****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origArgs := os.Args
			defer func() { os.Args = origArgs }()

			os.Args = tt.args
			got := formatArgs()
			if got != tt.expected {
				t.Errorf("formatArgs() = %q, want %q", got, tt.expected)
			}
		})
	}
}
