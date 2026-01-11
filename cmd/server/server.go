package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	phy "github.com/openbao/openbao/sdk/v2/physical"
	"github.com/spf13/cobra"
	wardenapi "github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth/method/jwt"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/core"
	wardenseal "github.com/stephnangue/warden/core/seal"
	wardenhttp "github.com/stephnangue/warden/http"
	"github.com/stephnangue/warden/internal/configutil"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/listener/api"
	log "github.com/stephnangue/warden/logger"
	wardenlogical "github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/physical"
	inmemStorage "github.com/stephnangue/warden/physical/inmem"
	postgresqlStorage "github.com/stephnangue/warden/physical/postgres"
	"github.com/stephnangue/warden/provider/aws"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// Subsystem names for logging
	subsystemCore        = "core"
	subsystemListener = "listener"

	// Listener type names
	listenerTypeTCP  = "tcp"
	listenerTypeUnix = "unix"
)

var (
	configPath string

	flagDevAutoSeal bool

	ServerCmd = &cobra.Command{
		Use:   "server",
		Short: "This command starts a Warden server that responds to API requests",
		Long: `
Usage: warden server [options]

  This command starts a Warden server that responds to API requests. By default,
  Start a server with a configuration file:

      $ warden server --config=/etc/warden/config.hcl

  For a full list of examples, please see the documentation.
  `,
		RunE: run,
	}

	wg sync.WaitGroup

	cleanupGuard sync.Once

	auditDevices = map[string]audit.Factory{
		"file": &audit.FileDeviceFactory{},
	}

	providers = map[string]wardenlogical.Factory{
		"aws": aws.Factory,
	}

	authMethods = map[string]wardenlogical.Factory{
		"jwt": jwt.Factory,
	}

	storageBackends = map[string]physical.Factory{
		"inmem_ha":   inmemStorage.NewInmemHA,
		"inmem":      inmemStorage.NewInmem,
		"postgres":   postgresqlStorage.NewPostgreSQLStorage,
	}
)

func init() {
	ServerCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to configuration file (e.g., path/to/warden.hcl)")
	ServerCmd.Flags().BoolVar(&flagDevAutoSeal, "dev-auto-seal", false, "Use autoseal in dev mode")
}

func run(cmd *cobra.Command, args []string) error {
	// Validate config path is provided
	if configPath == "" {
		return fmt.Errorf("config file path is required. Use -c or --config flag")
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", configPath)
	}

	// Load configuration
	config, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// construct the logger with gate closed during initialization
	logger := buildGatedLogger(config)

	// craft the storage
	storage, err := buildStorage(config, logger)
	if err != nil {
		return fmt.Errorf("failed to construct the storage: %w", err)
	}

	infoKeys := make([]string, 0, 10)
	info := make(map[string]string)
	info["log level"] = config.LogLevel
	infoKeys = append(infoKeys, "log level")
	info["log file"] = config.LogFile
	infoKeys = append(infoKeys, "log file")
	info["log format"] = config.LogFormat
	infoKeys = append(infoKeys, "log format")
	info["log rotate max files"] = fmt.Sprintf("%d", config.LogRotateMaxFiles)
	infoKeys = append(infoKeys, "log rotate max files")
	info["log rotate max size"] = fmt.Sprintf("%d", config.LogRotateMegabytes)
	infoKeys = append(infoKeys, "log rotate max size")
	info["log rotation period"] = fmt.Sprintf("%d", config.LogRotationPeriod)
	infoKeys = append(infoKeys, "log rotation period")

	// returns a slice of env vars formatted as "key=value"
	envVars := os.Environ()
	var envVarKeys []string
	for _, v := range envVars {
		splitEnvVars := strings.Split(v, "=")
		envVarKeys = append(envVarKeys, splitEnvVars[0])
	}

	sort.Strings(envVarKeys)

	key := "environment variables"
	info[key] = strings.Join(envVarKeys, ", ")
	infoKeys = append(infoKeys, key)

	barrierSeal, barrierWrapper, unwrapSeal, seals, sealConfigError, err := setSeal(config, logger, &infoKeys, info)
	// Check error here
	if err != nil {
		return fmt.Errorf("failed to set seal: %w", err)
	}

	for _, seal := range seals {
		// There is always one nil seal. We need to skip it so we don't start an empty Finalize-Seal-Shamir
		// section.
		if seal == nil {
			continue
		}
		seal := seal // capture range variable
		// Ensure that the seal finalizer is called, even if using verify-only
		defer func(seal *core.Seal) {
			err = (*seal).Finalize(context.Background())
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "error finalizing seals: %v\n", err)
			}
		}(&seal)
	}

	if barrierSeal == nil {
		return fmt.Errorf("could not create barrier seal! Most likely proper Seal configuration information was not set, but no error was generated")
	}

	// prepare a secure random reader for core
	// TODO : improve this, because it uses rand.Reader
	secureRandomReader, err := configutil.CreateSecureRandomReaderFunc(barrierWrapper)
	if err != nil {
		return fmt.Errorf("failed to create the secure random reader: %w", err)
	}

	coreConfig := createCoreConfig(logger, config, storage, barrierSeal, unwrapSeal, secureRandomReader)

	newCore, newCoreError := core.NewCore(&coreConfig)
	if newCoreError != nil {
		if core.IsFatalError(newCoreError) {
			return fmt.Errorf("error initializing core: %w", newCoreError)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "A non-fatal error occurred during initialization. Please check the logs for more information: %v\n", err )
	}

	// Compile server information for output later
	info["storage"] = config.Storage.Type
	infoKeys = append(infoKeys, "storage")

	if coreConfig.ClusterAddr != "" {
		info["cluster address"] = coreConfig.ClusterAddr
		infoKeys = append(infoKeys, "cluster address")
	}
	if coreConfig.RedirectAddr != "" {
		info["api address"] = coreConfig.RedirectAddr
		infoKeys = append(infoKeys, "api address")
	}

	// Create HTTP handler from core
	httpHandler := wardenhttp.Handler(&wardenhttp.HandlerProperties{
		Core:   newCore,
		Logger: logger,
	})

	// init the listeners
	lns, err := initListeners(httpHandler, config, logger, &infoKeys, &info)
	if err != nil {
		// Error already logged in initListeners
		return err
	}

	// Shutdown error tracking
	var shutdownErrs []error
	var shutdownErrsMu sync.Mutex

	// Make sure we close all listeners from this point on
	listenerCloseFunc := func() {
		fmt.Fprintf(cmd.OutOrStdout(), "Stopping all listeners\n")
		for _, ln := range lns {
			if err := ln.Stop(); err != nil {
				shutdownErrsMu.Lock()
				shutdownErrs = append(shutdownErrs, fmt.Errorf("failed to stop %s listener at %s: %w", ln.Type(), ln.Addr(), err))
				shutdownErrsMu.Unlock()
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Listener stopped successfully: type=%s, address=%s\n", ln.Type(), ln.Addr())
			}
		}
	}

	// Use sync.Once to ensure listeners are stopped exactly once, even if called
	// both via defer (on panic/error) and explicitly before core shutdown
	defer cleanupGuard.Do(listenerCloseFunc)

	sort.Strings(infoKeys)
	fmt.Fprintf(cmd.OutOrStdout(), "\n==> Warden server configuration:\n\n")

	titleCaser := cases.Title(language.English, cases.NoLower)
	
	for _, k := range infoKeys {
		fmt.Fprintf(cmd.OutOrStdout(), "%24s: %s\n", titleCaser.String(k), info[k])
	}

	// Attempt unsealing in a background goroutine. This is needed for when a
	// OpenBao cluster with multiple servers is configured with auto-unseal but is
	// uninitialized. Once one server initializes the storage backend, this
	// goroutine will pick up the unseal keys and unseal this instance.
	go runUnseal(cmd.Context(), newCore, context.Background())

	if sealConfigError != nil {
		init, err := newCore.InitializedLocally(context.Background())
		if err != nil {
			return fmt.Errorf("error checking if core is initialized: %w", err)
		}
		if init {
			return fmt.Errorf("warden is initialized but no Seal key could be loaded")
		}
	}

	// start the servers (HTTP and Database)
	// Use context from cobra command which respects signal interrupts
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// Channel to collect all listener errors
	errChan := make(chan error, len(lns))
	var listenerErrs []error
	var listenerErrsMu sync.Mutex
	totalListeners := len(lns)

	for _, ln := range lns {
		wg.Go(func() {
			if err := ln.Start(ctx); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "failed to start listener: %v\n", err)
				errChan <- err
			}
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\n==> Warden server started! Log data will stream in below:\n")
	logger.OpenGate()

	// Write out the PID to the file now that server has successfully started

	// Notify systemd that the server is ready (if applicable)

	// Wait for shutdown
	shutdownTriggered := false

	for !shutdownTriggered {
		select {
		case err := <-errChan:
			// Aggregate listener errors
			listenerErrsMu.Lock()
			listenerErrs = append(listenerErrs, err)
			failedCount := len(listenerErrs)
			listenerErrsMu.Unlock()

			fmt.Fprintf(cmd.OutOrStdout(), "Listener error occurred: failed_count=%d, total_listeners=%d\n", failedCount, totalListeners)

			// Only trigger shutdown if ALL listeners have failed
			if failedCount >= totalListeners {
				fmt.Fprintf(cmd.OutOrStdout(), "All listeners have failed, triggering shutdown: failed_count=%d\n", failedCount)
				shutdownTriggered = true
				cancel()
			}
		case <-ctx.Done():
			fmt.Fprintf(cmd.OutOrStdout(), "Warden shutdown triggered\n")
			shutdownTriggered = true
			cancel()
		}
	}

	// Notify systemd that the server is shutting down

	// Stop the listeners so that we don't process further client requests
	cleanupGuard.Do(listenerCloseFunc)

	// Wait for all listener goroutines to finish and collect any remaining errors
	wg.Wait()

	// Collect any remaining errors from errChan (non-blocking)
	close(errChan)
	for err := range errChan {
		listenerErrsMu.Lock()
		listenerErrs = append(listenerErrs, err)
		listenerErrsMu.Unlock()
	}

	// Log aggregated listener errors if any
	if len(listenerErrs) > 0 {
		aggregatedErr := errors.Join(listenerErrs...)
		fmt.Fprintf(cmd.OutOrStdout(), "Listener errors occurred during runtime: %v, error_count=%d\n", aggregatedErr, len(listenerErrs))
	}

	// Shutdown the core
	if err := newCore.Shutdown(); err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "core shutdown failed: %v\n", err)
		shutdownErrsMu.Lock()
		shutdownErrs = append(shutdownErrs, fmt.Errorf("core shutdown failed: %w", err))
		shutdownErrsMu.Unlock()
	}

	// Report aggregated shutdown errors
	if len(shutdownErrs) > 0 {
		aggregatedShutdownErr := errors.Join(shutdownErrs...)
		fmt.Fprintf(cmd.OutOrStdout(), "Shutdown completed with errors: %v, error_count=%d\n", aggregatedShutdownErr, len(shutdownErrs))
		return aggregatedShutdownErr
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Server shutdown completed successfully\n")
	return nil
}

func buildGatedLogger(config *config.Config) *log.GatedLogger {
	logConfig := &log.Config{
		Level:     log.ParseLogLevel(config.LogLevel),
		Subsystem: subsystemCore,
		FileConfig: &log.FileConfig{
			Filename:   config.LogFile,
			MaxSize:    config.LogRotateMegabytes,
			MaxAge:     config.LogRotationPeriod,
			MaxBackups: config.LogRotateMaxFiles,
		},
		Format:  log.ParseOutPutFormat(config.LogFormat),
		Outputs: []io.Writer{os.Stdout},
	}

	gateConfig := log.GatedWriterConfig{
		Underlying:    os.Stdout,
		InitialState:  log.GateClosed,
		MaxBufferSize: 10 * 1024 * 1024, // 10MB buffer for initialization logs
	}

	gatedLogger, _ := log.NewGatedLogger(logConfig, gateConfig)

	return gatedLogger
}

func buildStorage(config *config.Config, logger *log.GatedLogger) (phy.Backend, error) {
	// Ensure that a storage is provided
	if config.Storage == nil {
		return nil, errors.New("a storage backend must be specified")
	}

	factory, exists := storageBackends[config.Storage.Type]
	if !exists {
		return nil, fmt.Errorf("unknown storage type %s", config.Storage.Type)
	}

	storage, err := factory(config.Storage.Config(), logger.WithSystem("storage." + config.Storage.Type))

	if err != nil {
		return nil, fmt.Errorf("error initializing storage of type %s: %w", config.Storage.Type, err)
	}

	return storage, nil
}

func initListeners(httpHandler http.Handler, config *config.Config, logger *log.GatedLogger, infoKeys *[]string, info *map[string]string) ([]listener.Listener, error) {
	lns := make([]listener.Listener, 0, len(config.Listeners))

	for _, lnConfig := range config.Listeners {
		switch lnConfig.Type {
		case listenerTypeTCP, listenerTypeUnix:
			// construct api listener using shared HTTP handler
			ln, err := api.NewApiListener(api.ApiListenerConfig{
				Logger:          logger.WithSystem(subsystemListener),
				Address:         lnConfig.Address,
				TLSCertFile:     lnConfig.TLSCertFile,
				TLSKeyFile:      lnConfig.TLSKeyFile,
				TLSClientCAFile: lnConfig.TLSClientCAFile,
				TLSEnabled:      lnConfig.TLSEnabled,
			}, httpHandler)
			if err != nil {
				return nil, fmt.Errorf("error initializing listener of type %s: %s", lnConfig.Type, err)
			}
			lns = append(lns, ln)
		default:
			return nil, fmt.Errorf("unknown listener type: %s", lnConfig.Type)
		}
	}

	return lns, nil
}

// setSeal return barrierSeal, barrierWrapper, unwrapSeal, and all the created seals from the configs so we can close them in run
// The two errors are the sealConfigError and the regular error
func setSeal(conf *config.Config, logger *log.GatedLogger, infoKeys *[]string, info map[string]string) (core.Seal, wrapping.Wrapper, core.Seal, []core.Seal, error, error) {
	var barrierSeal core.Seal
	var unwrapSeal core.Seal

	var sealConfigError error
	var wrapper wrapping.Wrapper
	var barrierWrapper wrapping.Wrapper
	if flagDevAutoSeal {
		var err error
		access, _ := core.NewTestSeal(nil)
		barrierSeal, err = core.NewAutoSeal(access)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		return barrierSeal, nil, nil, nil, nil, nil
	}

	// Handle the case where no seal is provided
	switch len(conf.Seals) {
	case 0:
		conf.Seals = append(conf.Seals, config.KMS{Type: wrapping.WrapperTypeShamir.String()})
	case 1:
		// If there's only one seal and it's disabled assume they want to
		// migrate to a shamir seal and simply didn't provide it
		if conf.Seals[0].IsDisabled() {
			conf.Seals = append(conf.Seals, config.KMS{Type: wrapping.WrapperTypeShamir.String()})
		}
	}
	createdSeals := make([]core.Seal, len(conf.Seals))
	for _, configSeal := range conf.Seals {
		sealType := configSeal.Type
		if !conf.Seals[0].IsDisabled() && wardenapi.ReadWardenVariable("WARDEN_SEAL_TYPE") != "" {
			sealType = wardenapi.ReadWardenVariable("WARDEN_SEAL_TYPE")
			configSeal.Type = sealType
		}

		var seal core.Seal
		sealLogger := logger.WithSystem(fmt.Sprintf("seal.%s", sealType))
		defaultSeal := core.NewDefaultSeal(wardenseal.NewAccess(aeadwrapper.NewShamirWrapper()))
		var sealInfoKeys []string
		sealInfoMap := map[string]string{}
		wrapper, sealConfigError = configutil.ConfigureWrapper(&configSeal, &sealInfoKeys, &sealInfoMap, sealLogger)
		if sealConfigError != nil {
			if !errwrap.ContainsType(sealConfigError, new(logical.KeyNotFoundError)) {
				return barrierSeal, barrierWrapper, unwrapSeal, createdSeals, sealConfigError, fmt.Errorf(
					"Error parsing Seal configuration: %w", sealConfigError)
			}
		}
		if wrapper == nil {
			seal = defaultSeal
		} else {
			var err error
			seal, err = core.NewAutoSeal(wardenseal.NewAccess(wrapper))
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
		}
		infoPrefix := ""
		if configSeal.IsDisabled() {
			unwrapSeal = seal
			infoPrefix = "Old "
		} else {
			barrierSeal = seal
			barrierWrapper = wrapper
		}
		for _, k := range sealInfoKeys {
			*infoKeys = append(*infoKeys, infoPrefix+k)
			info[infoPrefix+k] = sealInfoMap[k]
		}
		createdSeals = append(createdSeals, seal)
	}
	return barrierSeal, barrierWrapper, unwrapSeal, createdSeals, sealConfigError, nil
}

func createCoreConfig(logger *log.GatedLogger, conf *config.Config, backend phy.Backend, barrierSeal, unwrapSeal core.Seal, secureRandomReader io.Reader,
) core.CoreConfig {
	coreConfig := &core.CoreConfig{
		RawConfig:                      conf,
		Physical:                       backend,
		RedirectAddr:                   conf.Storage.RedirectAddr,
		StorageType:                    conf.Storage.Type,
		HAPhysical:                     nil,
		Seal:                           barrierSeal,
		UnwrapSeal:                     unwrapSeal,
		AuditDevices:                   auditDevices,
		Providers:                      providers,
		AuthMethods:                    authMethods,
		Logger:                         logger,
		SecureRandomReader:             secureRandomReader,
	}
	return *coreConfig
}

func runUnseal(cmdContext context.Context, c *core.Core, ctx context.Context) {
	for {
		err := c.UnsealWithStoredKeys(ctx)
		if err == nil {
			return
		}

		if core.IsFatalError(err) {
			c.Logger().Error("error unsealing core", 
				log.Err(err),
			)
			return
		}
		c.Logger().Warn("failed to unseal core", 
			log.Err(err),
		)

		timer := time.NewTimer(5 * time.Second)
		select {
		case <-cmdContext.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}






