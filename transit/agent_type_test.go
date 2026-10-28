package transit

import "testing"

func TestWithAgentType(t *testing.T) {
	tests := []struct {
		name string
		meta map[string]string
		want int
	}{
		{"nil map", nil, 1},
		{"empty map", map[string]string{}, 1},
		{"existing keys kept", map[string]string{"hostname": "h"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := withAgentType(tt.meta, "sdk-client")
			if got["agent_type"] != "sdk-client" {
				t.Fatalf("agent_type = %q", got["agent_type"])
			}
			if len(got) != tt.want {
				t.Fatalf("len = %d, want %d", len(got), tt.want)
			}
		})
	}
}
