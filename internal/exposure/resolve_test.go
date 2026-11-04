package exposure

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveWindows(t *testing.T) {
	env := Env{
		GOOS: "windows",
		Home: `C:\Users\victim`,
		Lookup: func(k string) string {
			m := map[string]string{
				"APPDATA":      `C:\Users\victim\AppData\Roaming`,
				"LOCALAPPDATA": `C:\Users\victim\AppData\Local`,
				"PROGRAMDATA":  `C:\ProgramData`,
				"PROGRAMFILES": `C:\Program Files`,
				"USERPROFILE":  `C:\Users\victim`,
				"TEMP":         `C:\Users\victim\AppData\Local\Temp`,
			}
			return m[strings.ToUpper(k)]
		},
	}
	cases := []struct {
		raw, want string
	}{
		{`%APPDATA%\nikke_launcher`, `C:\Users\victim\AppData\Roaming\nikke_launcher`},
		{`%LOCALAPPDATA%\Google\Chrome\User Data`, `C:\Users\victim\AppData\Local\Google\Chrome\User Data`},
		{`%USERPROFILE%\code`, `C:\Users\victim\code`},
		{`%TEMP%\foo`, `C:\Users\victim\AppData\Local\Temp\foo`},
		{`~\.ssh\config`, `C:\Users\victim\.ssh\config`},
		{`~\.aws\credentials`, `C:\Users\victim\.aws\credentials`},
		{`C:\buildkite-agent\buildkite-agent.cfg`, `C:\buildkite-agent\buildkite-agent.cfg`},
		{`%PROGRAMFILES%\Git\etc\gitconfig`, `C:\Program Files\Git\etc\gitconfig`},
	}
	for _, tc := range cases {
		got := ResolvePath(env, tc.raw)
		if got.MissingVar != "" || got.Skip {
			t.Errorf("%s: missing=%s skip=%v note=%s", tc.raw, got.MissingVar, got.Skip, got.Note)
			continue
		}
		if got.Path != tc.want {
			t.Errorf("%s\n got %s\nwant %s", tc.raw, got.Path, tc.want)
		}
		if strings.Contains(got.Path, `/`) {
			t.Errorf("%s: windows path has slash: %s", tc.raw, got.Path)
		}
	}
}

func TestResolveLinux(t *testing.T) {
	env := Env{GOOS: "linux", Home: "/home/victim"}
	cases := []struct {
		raw, want string
	}{
		{`%APPDATA%\nikke_launcher`, `/home/victim/.config/nikke_launcher`},
		{`%LOCALAPPDATA%\Google\Chrome\User Data`, `/home/victim/.local/share/Google/Chrome/User Data`},
		{`%PROGRAMDATA%\Git\config`, `/var/lib/Git/config`},
		{`%USERPROFILE%\code`, `/home/victim/code`},
		{`~\.ssh\config`, `/home/victim/.ssh/config`},
		{`~\.aws\credentials`, `/home/victim/.aws/credentials`},
		{`%TEMP%\foo`, `/home/victim/tmp/foo`},
	}
	for _, tc := range cases {
		got := ResolvePath(env, tc.raw)
		if got.MissingVar != "" || got.Skip {
			t.Errorf("%s: missing=%s skip=%v note=%s", tc.raw, got.MissingVar, got.Skip, got.Note)
			continue
		}
		if got.Path != tc.want {
			t.Errorf("%s\n got %s\nwant %s", tc.raw, got.Path, tc.want)
		}
		if strings.Contains(got.Path, `\`) {
			t.Errorf("%s: linux path kept backslash: %s", tc.raw, got.Path)
		}
	}
	abs := ResolvePath(env, `C:\buildkite-agent\buildkite-agent.cfg`)
	if !abs.Skip {
		t.Fatalf("windows abs path should skip on linux, got %+v", abs)
	}
}

func TestResolveDarwin(t *testing.T) {
	env := Env{GOOS: "darwin", Home: "/Users/victim"}
	got := ResolvePath(env, `%APPDATA%\nikke_launcher`)
	want := `/Users/victim/Library/Application Support/nikke_launcher`
	if got.Path != want {
		t.Fatalf("got %s want %s", got.Path, want)
	}
	local := ResolvePath(env, `%LOCALAPPDATA%\foo`)
	if local.Path != `/Users/victim/Library/Application Support/foo` {
		t.Fatalf("local %s", local.Path)
	}
}

func TestResolveMissingEnv(t *testing.T) {
	env := Env{
		GOOS: "linux",
		Home: "/home/victim",
		Lookup: func(string) string {
			return ""
		},
	}
	got := ResolvePath(env, `$CLAUDE_CONFIG_DIR\.claude.json`)
	if got.MissingVar != "CLAUDE_CONFIG_DIR" {
		t.Fatalf("missing %q note %q", got.MissingVar, got.Note)
	}
	if got.Note != "environment variable not set" {
		t.Fatalf("note %q", got.Note)
	}
	envFile := ResolvePath(env, `$AWS_SHARED_CREDENTIALS_FILE`)
	if envFile.MissingVar != "AWS_SHARED_CREDENTIALS_FILE" {
		t.Fatalf("env file missing %q", envFile.MissingVar)
	}
}

func TestResolveDollarWhenSet(t *testing.T) {
	env := Env{
		GOOS: "linux",
		Home: "/home/victim",
		Lookup: func(k string) string {
			if strings.EqualFold(k, "CLAUDE_CONFIG_DIR") {
				return "/home/victim/.claude-alt"
			}
			return ""
		},
	}
	got := ResolvePath(env, `$CLAUDE_CONFIG_DIR\.claude.json`)
	if got.Path != "/home/victim/.claude-alt/.claude.json" {
		t.Fatalf("got %s", got.Path)
	}
}

func TestResolveXDGOverride(t *testing.T) {
	env := Env{
		GOOS: "linux",
		Home: "/home/victim",
		Lookup: func(k string) string {
			if k == "XDG_CONFIG_HOME" {
				return "/home/victim/.xdg-config"
			}
			return ""
		},
	}
	got := ResolvePath(env, `%APPDATA%\nikke_launcher`)
	if got.Path != "/home/victim/.xdg-config/nikke_launcher" {
		t.Fatalf("got %s", got.Path)
	}
}

func TestResolvePercent04xNotEnv(t *testing.T) {
	env := Env{GOOS: "windows", Home: `C:\Users\victim`}
	got := ResolvePath(env, `\u%04x`)
	if got.MissingVar != "" {
		t.Fatalf("treated %%04x as env: %+v", got)
	}
}

func TestResolveWinePrefix(t *testing.T) {
	env := Env{
		GOOS:       "linux",
		Home:       "/home/victim",
		WinePrefix: "/home/victim/.steam/steam/steamapps/compatdata/1234/pfx",
		WineUser:   "steamuser",
	}
	got := ResolvePath(env, `%APPDATA%\nikke_launcher`)
	want := "/home/victim/.steam/steam/steamapps/compatdata/1234/pfx/drive_c/users/steamuser/AppData/Roaming/nikke_launcher"
	if got.Path != want {
		t.Fatalf("got %s want %s", got.Path, want)
	}
	abs := ResolvePath(env, `C:\buildkite-agent\buildkite-agent.cfg`)
	if !strings.HasSuffix(abs.Path, "/drive_c/buildkite-agent/buildkite-agent.cfg") {
		t.Fatalf("wine abs %s", abs.Path)
	}
}

func TestExpandGlobCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 25; i++ {
		writeFile(t, filepath.Join(dir, "f"+itoa(i)+".txt"), "x")
	}
	pattern := filepath.Join(dir, "*.txt")
	matches, truncated, err := expandGlob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("expected truncation")
	}
	if len(matches) != globCap {
		t.Fatalf("len %d", len(matches))
	}
}

func TestFixtureLookupUsesHome(t *testing.T) {
	home := t.TempDir()
	env := fixtureEnv(runtime.GOOS, home)
	got := ResolvePath(env, `~\.ssh\config`)
	want := filepath.Join(home, ".ssh", "config")
	if got.Path != want {
		t.Fatalf("got %s want %s", got.Path, want)
	}
}
