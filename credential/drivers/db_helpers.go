package drivers

// defaultPortForEngine returns the standard port for common database engines.
func defaultPortForEngine(engine string) string {
	switch engine {
	case "mysql":
		return "3306"
	default: // postgres
		return "5432"
	}
}
