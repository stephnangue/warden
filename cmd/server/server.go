package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/auth"
	"github.com/stephnangue/warden/auth/method/jwt"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/listener/api"
	"github.com/stephnangue/warden/listener/mysql"
	log "github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/physical"
	fileStorage "github.com/stephnangue/warden/physical/file"
	inmemStorage "github.com/stephnangue/warden/physical/inmem"
	postgresqlStorage "github.com/stephnangue/warden/physical/postgres"
	"github.com/stephnangue/warden/provider"
	"github.com/stephnangue/warden/provider/aws"
)

const (
	// Subsystem names for logging
	subsystemCore          = "core"
	subsystemInit          = "init"
	subsystemToken         = "token"
	subsystemAPIListener   = "api-listener"
	subsystemMySQLListener = "mysql-listener"

	// Listener type names
	listenerTypeAPI   = "api"
	listenerTypeMySQL = "mysql"
)

var (
	configPath string

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

	providers = map[string]provider.Factory{
		"aws": &aws.AWSProviderFactory{},
	}

	authMethods = map[string]auth.Factory{
		"jwt": &jwt.JWTAuthMethodFactory{},
	}

	storageBackends = map[string]physical.Factory{
		"file":       fileStorage.NewFileBackend,
		"inmem_ha":   inmemStorage.NewInmemHA,
		"inmem":      inmemStorage.NewInmem,
		"postgres": postgresqlStorage.NewPostgreSQLStorage,
	}
)

func init() {
	ServerCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to configuration file (e.g., path/to/warden.hcl)")
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

	// construct the logger
	logger := buildLogger(config)

	initLogger := logger.WithSystem(subsystemInit)

	// craft the storage
	storage, err := buildStorage(config, initLogger)
	if err != nil {
		initLogger.Error("failed to construct the storage", log.Err(err))
		return fmt.Errorf("failed to construct the storage: %w", err)
	}

	// craft the token store
	tokenStore, err := token.NewRobustStore(logger.WithSystem(subsystemToken), token.DefaultConfig())
	if err != nil {
		initLogger.Error("failed to create the token store", log.Err(err))
		return fmt.Errorf("failed to create the token store: %w", err)
	}

	// create the core config
	coreConfig := core.CoreConfig{
		RawConfig:    config,
		AuditDevices: auditDevices,
		AuthMethods:  authMethods,
		Providers:    providers,
		TokenStore:   tokenStore,
		Storage:      storage,
		Logger:       logger,
	}

	// create the core
	core, err := core.CreateCore(&coreConfig)
	if err != nil {
		initLogger.Error("failed to construct the core", log.Err(err))
		return fmt.Errorf("failed to construct the core: %w", err)
	}

	// init the core
	err = core.Init(cmd.Context())
	if err != nil {
		initLogger.Error("failed to initialize the core", log.Err(err))
		return fmt.Errorf("failed to initialize the core: %w", err)
	}

	// init the listeners
	lns, err := initListeners(core, tokenStore, config, initLogger)
	if err != nil {
		// Error already logged in initListeners
		return err
	}

	// Shutdown error tracking
	var shutdownErrs []error
	var shutdownErrsMu sync.Mutex

	// Make sure we close all listeners from this point on
	listenerCloseFunc := func() {
		initLogger.Info("Stopping all listeners")
		for _, ln := range lns {
			if err := ln.Stop(); err != nil {
				initLogger.Error("Error stopping listener",
					log.String("type", ln.Type()),
					log.String("address", ln.Addr()),
					log.Err(err))
				shutdownErrsMu.Lock()
				shutdownErrs = append(shutdownErrs, fmt.Errorf("failed to stop %s listener at %s: %w", ln.Type(), ln.Addr(), err))
				shutdownErrsMu.Unlock()
			} else {
				initLogger.Info("Listener stopped successfully",
					log.String("type", ln.Type()),
					log.String("address", ln.Addr()))
			}
		}
	}

	// Use sync.Once to ensure listeners are stopped exactly once, even if called
	// both via defer (on panic/error) and explicitly before core shutdown
	defer cleanupGuard.Do(listenerCloseFunc)

	// start the servers (HTTP and Database)
	initLogger.Info("Starting all listeners")
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
				initLogger.Error("failed to start listener", log.Err(err))
				errChan <- err
			}
		})
	}

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

			initLogger.Error("Listener error occurred",
				log.Err(err),
				log.Int("failed_count", failedCount),
				log.Int("total_listeners", totalListeners))

			// Only trigger shutdown if ALL listeners have failed
			if failedCount >= totalListeners {
				initLogger.Error("All listeners have failed, triggering shutdown",
					log.Int("failed_count", failedCount))
				shutdownTriggered = true
				cancel()
			}
		case <-ctx.Done():
			initLogger.Info("Warden shutdown triggered")
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
		initLogger.Error("Listener errors occurred during runtime",
			log.Err(aggregatedErr),
			log.Int("error_count", len(listenerErrs)))
	}

	// Shutdown the core
	if err := core.Shutdown(); err != nil {
		initLogger.Error("Error with core shutdown", log.Err(err))
		shutdownErrsMu.Lock()
		shutdownErrs = append(shutdownErrs, fmt.Errorf("core shutdown failed: %w", err))
		shutdownErrsMu.Unlock()
	}

	// Report aggregated shutdown errors
	if len(shutdownErrs) > 0 {
		aggregatedShutdownErr := errors.Join(shutdownErrs...)
		initLogger.Error("Shutdown completed with errors",
			log.Err(aggregatedShutdownErr),
			log.Int("error_count", len(shutdownErrs)))
		return aggregatedShutdownErr
	}

	initLogger.Info("Server shutdown completed successfully")
	return nil
}

func buildLogger(config *config.Config) log.Logger {
	logConfig := log.Config{
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

	logger := log.NewZerologLogger(&logConfig)

	return logger
}

func buildStorage(config *config.Config, logger log.Logger) (physical.Storage, error) {
	logger.Info("initializing the storage")
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

	logger.Info("storage successfully initialized")
	return storage, nil
}

func initListeners(core *core.Core, tokenAccess token.TokenStore, config *config.Config, logger log.Logger) ([]listener.Listener, error) {
	lns := make([]listener.Listener, 0, len(config.Listeners))

	for _, lnConfig := range config.Listeners {
		switch lnConfig.Name {
		case listenerTypeAPI:
			// construct api listerner
			ln, err := api.NewApiListener(api.ApiListenerConfig{
				Logger:          logger.WithSystem(subsystemAPIListener),
				Protocol:        lnConfig.Protocol,
				Address:         lnConfig.Address,
				TLSCertFile:     lnConfig.TLSCertFile,
				TLSKeyFile:      lnConfig.TLSKeyFile,
				TLSClientCAFile: lnConfig.TLSClientCAFile,
				TLSEnabled:      lnConfig.TLSEnabled,
			}, core)
			if err != nil {
				logger.Error("failed to create listener",
					log.Err(err),
				)
				return nil, fmt.Errorf("error initializing listener of type %s: %s", listenerTypeAPI, err)
			}
			lns = append(lns, ln)
		case listenerTypeMySQL:
			// construct mysql listerner
			listenerConf := mysql.MysqlListenerConfig{
				Protocol:        lnConfig.Protocol,
				Address:         lnConfig.Address,
				Roles:           core.Roles(),
				CredSources:     core.CredSources(),
				Targets:         core.Targets(),
				Logger:          logger.WithSystem(subsystemMySQLListener),
				TLSCertFile:     lnConfig.TLSCertFile,
				TLSKeyFile:      lnConfig.TLSKeyFile,
				TLSClientCAFile: lnConfig.TLSClientCAFile,
				TLSEnabled:      lnConfig.TLSEnabled,
				TokenStore:      tokenAccess,
			}

			ln, err := mysql.NewMysqlListener(listenerConf)
			if err != nil {
				logger.Error("failed to create listener",
					log.Err(err),
				)
				return nil, fmt.Errorf("error initializing listener of type %s: %s", listenerTypeMySQL, err)
			}
			lns = append(lns, ln)
		}
	}

	return lns, nil
}
