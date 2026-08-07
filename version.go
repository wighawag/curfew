package main

import "runtime/debug"

// version is the curfew version string. For a release build it is stamped
// via -ldflags "-X main.version=<tag>". When it is left at the default "dev"
// (a plain `go build`, or `go install ...@vX`), resolveVersion falls back to
// the module version and VCS revision from the build info, so an installed
// binary still reports something real.
var version = "dev"

// isVersionArg reports whether the argv asks for the version.
func isVersionArg(args []string) bool {
	return len(args) == 1 && (args[0] == "--version" || args[0] == "version")
}

func resolveVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			rev := s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
			return "dev+" + rev
		}
	}
	return version
}
