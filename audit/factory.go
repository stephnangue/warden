package audit

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/logger"
)

type FileDeviceFactory struct {
	logger *logger.GatedLogger
}

func (f *FileDeviceFactory) Type() string {
	return "file"
}

func (f *FileDeviceFactory) Class() string {
	return "audit"
}

func (f *FileDeviceFactory) Initialize(log *logger.GatedLogger) error {
	f.logger = log.WithSubsystem(f.Type())

	return nil
}

func (f *FileDeviceFactory) Create(
	ctx context.Context,
	mountPath string,
	description string,
	accessor string,
	config map[string]any,
) (Device, error) {

	conf, err := mapToFileDeviceConfig(config)
	if err != nil {
		return nil, err
	}

	// we only support json format for now
	if conf.Format != "json" {
		return nil, fmt.Errorf("unsupported audit log format: %s", conf.Format)
	}

	var fileMode os.FileMode = 0600 // default mode
	if conf.Mode != "" {
		parsedMode, err := strconv.ParseUint(conf.Mode, 8, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid file mode: %v", err)
		}
		fileMode = os.FileMode(parsedMode)
	}

	fileSink, err := NewFileSink(FileSinkConfig{
		Path:        conf.Path,
		RotateSize:  conf.RotateSize,
		RotateDaily: conf.RotateDaily,
		MaxBackups:  conf.MaxBackups,
		Mode:        fileMode,
	})
	if err != nil {
		return nil, err
	}

	bufferedSink, err := NewBufferedSink(BufferedSinkConfig{
		Sink:        fileSink,
		BufferSize:  conf.BufferSize,
		FlushPeriod: conf.FlushPeriod,
		Logger:      f.logger,
	})
	if err != nil {
		return nil, err
	}

	if accessor == "" {
		randID := helper.GenerateShortID()
		accessor = fmt.Sprintf("%s_%s", f.Type(), randID)
	}

	jsonFormat, warnings := jsonFormatFor(conf)

	device := NewDevice(mountPath, jsonFormat, bufferedSink, &DeviceConfig{
		Name:        mountPath,
		Type:        f.Type(),
		Class:       f.Class(),
		Description: description,
		Enabled:     conf.Enabled,
		Format:      conf.Format,
		Accessor:    accessor,
		BufferSize:  conf.BufferSize,
		FlushPeriod: conf.FlushPeriod,
		Warnings:    warnings,
	})

	return device, nil
}

// jsonFormatFor builds the device's format from its configuration, with the
// warnings to report for what it had to change.
//
// A salt path needs the device's HMAC key. Without one, every salt path is
// omitted instead: the value is dropped rather than written in clear. Core
// generates a key for every device it enables, so this is a device whose
// stored configuration lost it.
func jsonFormatFor(conf *FileDeviceConfig) (*JSONFormat, []string) {
	var opts []JSONFormatOption
	var warnings []string

	if conf.Prefix != "" {
		opts = append(opts, WithPrefix(conf.Prefix))
	}

	omit := conf.OmitFields
	switch {
	case len(conf.SaltFields) == 0:
	case conf.HMACKey != "":
		opts = append(opts, WithSaltFunc(NewHMACer(conf.HMACKey).SaltFunc()), WithSaltFields(conf.SaltFields))
	default:
		omit = fieldPaths(omit, conf.SaltFields, false)
		warnings = append(warnings, fmt.Sprintf("no hmac_key: these fields are omitted instead of salted: %v", conf.SaltFields))
	}

	if len(omit) > 0 {
		opts = append(opts, WithOmitFields(omit))
	}

	return NewJSONFormat(opts...), warnings
}
