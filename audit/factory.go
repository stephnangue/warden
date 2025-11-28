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
	logger logger.Logger
}

func (f *FileDeviceFactory) Type() string {
	return "file"
}

func (f *FileDeviceFactory) Class() string {
	return "audit"
}

func (f *FileDeviceFactory) Initialize(log logger.Logger) error {
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
	})
	if err != nil {
		return nil, err
	}

	if accessor == "" {
		randID := helper.GenerateShortID()
		accessor = fmt.Sprintf("%s_%s", f.Type(), randID)
	}

	// Create format with optional salting and omission if configured
	var jsonFormat *JSONFormat
	var formatOpts []JSONFormatOption

	// Always add prefix if configured
	if conf.Prefix != "" {
		formatOpts = append(formatOpts, WithPrefix(conf.Prefix))
	}

	// Add salting if configured
	if conf.HMACKey != "" && len(conf.SaltFields) > 0 {
		hmacer := NewHMACer(conf.HMACKey)
		formatOpts = append(formatOpts, WithSaltFunc(hmacer.SaltFunc()))
		formatOpts = append(formatOpts, WithSaltFields(conf.SaltFields))
	}

	// Add omit fields if configured
	if len(conf.OmitFields) > 0 {
		formatOpts = append(formatOpts, WithOmitFields(conf.OmitFields))
	}

	jsonFormat = NewJSONFormat(formatOpts...)

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
	})

	return device, nil
}
