package scanner

// IsNmapInstalled checks if nmap is available (exported for use in main)
func IsNmapInstalled() bool {
	return isNmapInstalled()
}
