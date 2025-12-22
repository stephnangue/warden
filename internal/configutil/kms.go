package configutil

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hashicorp/errwrap"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/alicloudkms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/awskms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/azurekeyvault/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/gcpckms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/kmip/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/ocikms/v2"
	statickms "github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/transit/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/logger"
)

var (
	ConfigureWrapper             = configureWrapper
	CreateSecureRandomReaderFunc = createSecureRandomReader
)

// Entropy contains Entropy configuration for the server
type EntropyMode int

const (
	EntropyUnknown EntropyMode = iota
	EntropyAugmentation
)

type Entropy struct {
	Mode EntropyMode
}

func configureWrapper(configKMS *config.KMS, infoKeys *[]string, info *map[string]string, logger *logger.GatedLogger, opts ...wrapping.Option) (wrapping.Wrapper, error) {
	var wrapper wrapping.Wrapper
	var kmsInfo map[string]string
	var err error

	switch wrapping.WrapperType(configKMS.Type) {
	case wrapping.WrapperTypeShamir:
		return nil, nil

	case wrapping.WrapperTypeAliCloudKms:
		wrapper, kmsInfo, err = GetAliCloudKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeAwsKms:
		wrapper, kmsInfo, err = GetAWSKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeAzureKeyVault:
		wrapper, kmsInfo, err = GetAzureKeyVaultKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeGcpCkms:
		wrapper, kmsInfo, err = GetGCPCKMSKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeOciKms:
		if keyId, ok := configKMS.Config()["key_id"]; ok {
			opts = append(opts, wrapping.WithKeyId(keyId))
		}
		wrapper, kmsInfo, err = GetOCIKMSKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeTransit:
		wrapper, kmsInfo, err = GetTransitKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeKmip:
		wrapper, kmsInfo, err = GetKmipKMSFunc(configKMS, opts...)

	case wrapping.WrapperTypeStatic:
		wrapper, kmsInfo, err = GetStaticKMSFunc(configKMS, opts...)

	default:
		return nil, fmt.Errorf("unknown KMS type %q", configKMS.Type)
	}

	if err != nil {
		return nil, err
	}

	if infoKeys != nil && info != nil {
		for k, v := range kmsInfo {
			*infoKeys = append(*infoKeys, k)
			(*info)[k] = v
		}
	}

	return wrapper, nil
}

func GetAliCloudKMSFunc(kms *config.KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := alicloudkms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config()))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["AliCloud KMS Region"] = wrapperInfo.Metadata["region"]
		info["AliCloud KMS KeyID"] = wrapperInfo.Metadata["kms_key_id"]
		if domain, ok := wrapperInfo.Metadata["domain"]; ok {
			info["AliCloud KMS Domain"] = domain
		}
	}
	return wrapper, info, nil
}

var GetAWSKMSFunc = func(kms *config.KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := awskms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config()))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["AWS KMS Region"] = wrapperInfo.Metadata["region"]
		info["AWS KMS KeyID"] = wrapperInfo.Metadata["kms_key_id"]
		if endpoint, ok := wrapperInfo.Metadata["endpoint"]; ok {
			info["AWS KMS Endpoint"] = endpoint
		}
	}
	return wrapper, info, nil
}


func GetAzureKeyVaultKMSFunc(kms *config.KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := azurekeyvault.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config()))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["Azure Environment"] = wrapperInfo.Metadata["environment"]
		info["Azure Vault Name"] = wrapperInfo.Metadata["vault_name"]
		info["Azure Key Name"] = wrapperInfo.Metadata["key_name"]
	}
	return wrapper, info, nil
}

func GetGCPCKMSKMSFunc(kms *config.KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := gcpckms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config()))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["GCP KMS Project"] = wrapperInfo.Metadata["project"]
		info["GCP KMS Region"] = wrapperInfo.Metadata["region"]
		info["GCP KMS Key Ring"] = wrapperInfo.Metadata["key_ring"]
		info["GCP KMS Crypto Key"] = wrapperInfo.Metadata["crypto_key"]
	}
	return wrapper, info, nil
}

func GetOCIKMSKMSFunc(kms *config.KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := ocikms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config()))...)
	if err != nil {
		return nil, nil, err
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["OCI KMS KeyID"] = wrapperInfo.Metadata[ocikms.KmsConfigKeyId]
		info["OCI KMS Crypto Endpoint"] = wrapperInfo.Metadata[ocikms.KmsConfigCryptoEndpoint]
		info["OCI KMS Management Endpoint"] = wrapperInfo.Metadata[ocikms.KmsConfigManagementEndpoint]
		info["OCI KMS Principal Type"] = wrapperInfo.Metadata["principal_type"]
	}
	return wrapper, info, nil
}

var GetTransitKMSFunc = func(kms *config.KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := transit.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config()))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		info["Transit Address"] = wrapperInfo.Metadata["address"]
		info["Transit Mount Path"] = wrapperInfo.Metadata["mount_path"]
		info["Transit Key Name"] = wrapperInfo.Metadata["key_name"]
		if namespace, ok := wrapperInfo.Metadata["namespace"]; ok {
			info["Transit Namespace"] = namespace
		}
	}
	return wrapper, info, nil
}

func GetKmipKMSFunc(kms *config.KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := kmip.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config()))...)
	if err != nil {
		return nil, nil, err
	}

	info := make(map[string]string)
	if wrapperInfo != nil {
		info["KMIP Key ID"] = wrapperInfo.Metadata["kms_key_id"]
		info["KMIP Endpoint"] = wrapperInfo.Metadata["endpoint"]
		info["KMIP Timeout"] = wrapperInfo.Metadata["timeout"]
		info["KMIP Encryption Algorithm"] = wrapperInfo.Metadata["encrypt_alg"]
		info["KMIP Protocol Version"] = wrapperInfo.Metadata["kmip_version"]

		if tlsCiphers := wrapperInfo.Metadata["kmip_tls12_ciphers"]; tlsCiphers != "" {
			info["KMIP TLS 1.2 Ciphers"] = tlsCiphers
		}
		if pubKeyId := wrapperInfo.Metadata["kms_public_key_id"]; pubKeyId != "" {
			info["KMIP Public Key ID"] = pubKeyId
		}
		if serverName := wrapperInfo.Metadata["server_name"]; serverName != "" {
			info["KMIP Server Name"] = serverName
		}
	}
	return wrapper, info, nil
}

func GetStaticKMSFunc(kms *config.KMS, opts ...wrapping.Option) (wrapping.Wrapper, map[string]string, error) {
	wrapper := statickms.NewWrapper()
	wrapperInfo, err := wrapper.SetConfig(context.Background(), append(opts, wrapping.WithConfigMap(kms.Config()))...)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, nil, err
		}
	}
	info := make(map[string]string)
	if wrapperInfo != nil {
		if prev, ok := wrapperInfo.Metadata["previous_key_id"]; ok {
			info["Static KMS Previous Key ID"] = prev
		}
		info["Static KMS Key ID"] = wrapperInfo.Metadata["current_key_id"]
	}
	return wrapper, info, nil
}

func createSecureRandomReader(wrapper wrapping.Wrapper) (io.Reader, error) {
	return rand.Reader, nil
}