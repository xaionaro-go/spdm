package algo

import "fmt"

// Version represents a short SPDM version (major.minor) encoded as major<<4 | minor.
type Version uint16

const (
	Version10 Version = 0x10
	Version11 Version = 0x11
	Version12 Version = 0x12
	Version13 Version = 0x13
	Version14 Version = 0x14
)

// Major returns the major version number.
func (v Version) Major() uint8 { return uint8(v >> 4) }

// Minor returns the minor version number.
func (v Version) Minor() uint8 { return uint8(v & 0x0F) }

// String returns the version as "major.minor".
func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major(), v.Minor()) }

// VersionFromParts creates a Version from major and minor components.
func VersionFromParts(major, minor uint8) Version { return Version(major<<4 | minor) }

// VersionNumber is the full 16-bit version as on wire (major<<12 | minor<<8 | update<<4 | alpha).
type VersionNumber uint16

// Major returns the major version number.
func (v VersionNumber) Major() uint8 { return uint8(v >> 12) }

// Minor returns the minor version number.
func (v VersionNumber) Minor() uint8 { return uint8((v >> 8) & 0x0F) }

// Update returns the update version number.
func (v VersionNumber) Update() uint8 { return uint8((v >> 4) & 0x0F) }

// Alpha returns the alpha version number.
func (v VersionNumber) Alpha() uint8 { return uint8(v & 0x0F) }

// Version converts a VersionNumber to a short Version (discarding update and alpha).
func (v VersionNumber) Version() Version {
	return Version(uint8(v>>12)<<4 | uint8((v>>8)&0x0F))
}

// String returns the version number as "major.minor.update.alpha".
func (v VersionNumber) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", v.Major(), v.Minor(), v.Update(), v.Alpha())
}
