package containers_test

import (
	"testing"

	"github.com/QYVORA/qyvora-imhotep/internal/containers"
)

func TestInspectDockerfile(t *testing.T) {
	content := "FROM node:18\nUSER root\nWORKDIR /app\nCMD [\"npm\",\"start\"]\n"
	flags := containers.Inspect("docker", content)
	if !hasKind(flags, "runs_as_root") {
		t.Errorf("expected runs_as_root: %+v", flags)
	}
	for _, f := range flags {
		if f.Line <= 0 {
			t.Errorf("flag missing line: %+v", f)
		}
	}
}

func TestInspectKubernetes(t *testing.T) {
	content := "spec:\n  template:\n    spec:\n      containers:\n      - name: web\n        image: nginx:latest\n        securityContext:\n          privileged: true\n      hostNetwork: true\n"
	flags := containers.Inspect("k8s", content)
	for _, want := range []string{"privileged", "host_network", "latest_tag"} {
		if !hasKind(flags, want) {
			t.Errorf("expected %s: %+v", want, flags)
		}
	}
}

func TestInspectCleanManifest(t *testing.T) {
	content := "image: nginx:1.27.3\ndisabled: true\nhostname: notNetwork\n"
	flags := containers.Inspect("k8s", content)
	if len(flags) != 0 {
		t.Errorf("clean manifest flagged: %+v", flags)
	}
}

func hasKind(flags []containers.Flag, kind string) bool {
	for _, f := range flags {
		if f.Kind == kind {
			return true
		}
	}
	return false
}
