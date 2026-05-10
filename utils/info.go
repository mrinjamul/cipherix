/*Package utils ...
 *
 */
package utils

// Version is set at build time via -ldflags.
// Default fallback for local builds without ldflags.
var Version = "dev"

// GetVersion return the version of the application
func GetVersion() string {
	return Version
}
