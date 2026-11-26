package main

import (
	"flag"
	"os"
	"strings"
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

func TestExpandListArgs(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	var interfaces, masquerade stringSlice
	flags.Var(&interfaces, "interfaces", "")
	flags.Var(&masquerade, "masquerade", "")
	flags.Bool("verbose", false, "")
	flags.Int("ttl", 0, "")

	tests := []struct {
		name, args, want string
		wantErr          bool
	}{
		{name: "values after a list flag", args: "--interfaces a b c", want: "--interfaces a --interfaces b --interfaces c"},
		{name: "each list keeps its values", args: "-masquerade a b --interfaces c d", want: "-masquerade a --masquerade b --interfaces c --interfaces d"},
		{name: "inline first value", args: "--masquerade=a b", want: "--masquerade=a --masquerade b"},
		{name: "flags after a list", args: "--interfaces a b --verbose --ttl 3", want: "--interfaces a --interfaces b --verbose --ttl 3"},
		{name: "unknown flag is left to the parser", args: "--nonsense", want: "--nonsense"},
		{name: "loose value after a switch", args: "--interfaces a --verbose b", wantErr: true},
		{name: "loose value after a single-value flag", args: "--ttl 3 b", wantErr: true},
		{name: "loose value first", args: "a --verbose", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandListArgs(flags, strings.Fields(tt.args))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %t", err, tt.wantErr)
			}
			if joined := strings.Join(got, " "); !tt.wantErr && joined != tt.want {
				t.Errorf("got %q, want %q", joined, tt.want)
			}
		})
	}
}

func TestValidateListenAddr(t *testing.T) {
	for addr, ok := range map[string]bool{
		"192.0.2.1": true, "": false, "relay.example.com": false, "2001:db8::1": false, "192.0.2.0/24": false,
	} {
		if err := validateListenAddr(addr); (err == nil) != ok {
			t.Errorf("validateListenAddr(%q) = %v, want accepted %t", addr, err, ok)
		}
	}
}
