package config

func (c *Config) GetStorage() *StorageBlock {
	return c.Storage
}

// mergeConfig copies non-zero fields from src into dst, so a sequence of
// loaded configs collapses to a single merged *Config with "later wins"
// semantics. Slice and pointer block fields (Listeners, Storage, Seals)
// are replaced wholesale when src defines them — there is no per-field
// merge inside a block, which matches how operators typically split
// secret vs non-secret HCL (one file owns each block entirely).
func mergeConfig(dst, src *Config) {
	if src.LogLevel != "" {
		dst.LogLevel = src.LogLevel
	}
	if src.LogFormat != "" {
		dst.LogFormat = src.LogFormat
	}
	if src.LogFile != "" {
		dst.LogFile = src.LogFile
	}
	if src.LogRotationPeriod != 0 {
		dst.LogRotationPeriod = src.LogRotationPeriod
	}
	if src.LogRotateMegabytes != 0 {
		dst.LogRotateMegabytes = src.LogRotateMegabytes
	}
	if src.LogRotateMaxFiles != 0 {
		dst.LogRotateMaxFiles = src.LogRotateMaxFiles
	}
	if len(src.Listeners) > 0 {
		dst.Listeners = src.Listeners
	}
	if src.Storage != nil {
		dst.Storage = src.Storage
	}
	if len(src.Seals) > 0 {
		dst.Seals = src.Seals
	}
	if src.APIAddr != "" {
		dst.APIAddr = src.APIAddr
	}
	if src.ClusterAddr != "" {
		dst.ClusterAddr = src.ClusterAddr
	}
	if src.DisableClustering {
		dst.DisableClustering = true
	}
	if src.DisableStandbyReads {
		dst.DisableStandbyReads = true
	}
	if src.MinCredSourceRotationPeriod != "" {
		dst.MinCredSourceRotationPeriod = src.MinCredSourceRotationPeriod
	}
	if src.MaxCredSourceRotationPeriod != "" {
		dst.MaxCredSourceRotationPeriod = src.MaxCredSourceRotationPeriod
	}
	if src.MinCredSpecRotationPeriod != "" {
		dst.MinCredSpecRotationPeriod = src.MinCredSpecRotationPeriod
	}
	if src.MaxCredSpecRotationPeriod != "" {
		dst.MaxCredSpecRotationPeriod = src.MaxCredSpecRotationPeriod
	}
	if src.IPBindingPolicy != "" {
		dst.IPBindingPolicy = src.IPBindingPolicy
	}
	if src.GoroutineShutdownTimeout != "" {
		dst.GoroutineShutdownTimeout = src.GoroutineShutdownTimeout
	}
	if src.LockAcquisitionTimeout != "" {
		dst.LockAcquisitionTimeout = src.LockAcquisitionTimeout
	}
	if src.LeaderCleanupInterval != "" {
		dst.LeaderCleanupInterval = src.LeaderCleanupInterval
	}
	if src.StepDownStateLockTimeout != "" {
		dst.StepDownStateLockTimeout = src.StepDownStateLockTimeout
	}
	if src.LeaderLookupTimeout != "" {
		dst.LeaderLookupTimeout = src.LeaderLookupTimeout
	}
	if src.ClockSkewGrace != "" {
		dst.ClockSkewGrace = src.ClockSkewGrace
	}
	if src.ClusterListenerReadTimeout != "" {
		dst.ClusterListenerReadTimeout = src.ClusterListenerReadTimeout
	}
	if src.ClusterListenerWriteTimeout != "" {
		dst.ClusterListenerWriteTimeout = src.ClusterListenerWriteTimeout
	}
	if src.ForwardingTimeout != "" {
		dst.ForwardingTimeout = src.ForwardingTimeout
	}
}
