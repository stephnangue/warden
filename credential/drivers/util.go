package drivers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/remotesign"
)

// parseSecretPayload turns raw secret bytes into the credential's fields. It is shared
// by the stores whose secrets are opaque strings — GCP Secret Manager and
// Azure Key Vault — so a payload means the same thing whichever of them holds it.
//
// Such a store holds arbitrary bytes, so unlike a store that holds documents there is
// no single right shape. A JSON object of scalars is vended under its own key names
// — the multi-field secret a chained consumer reads by name, with numbers and booleans
// rendered as strings because that is the only shape this credential type carries.
// Anything that is not a JSON object at all, a plain API key being the common case, is
// vended whole under "value".
//
// A document containing a nested object or array is refused rather than vended either
// way. Blobbing it under "value" would be actively dangerous: a consuming spec that
// names no secret_field takes the sole key when there is only one, so the entire
// document — every secret stored beside the wanted one — would be sent upstream as the
// credential. Dropping the nested field and keeping the rest would be quietly lossy.
// Neither is worth the convenience of accepting a shape nothing here can represent.
func parseSecretPayload(decoded []byte) (map[string]interface{}, error) {
	var fields map[string]interface{}
	if err := json.Unmarshal(decoded, &fields); err != nil || fields == nil {
		// Not a JSON object: the payload is one opaque secret.
		return map[string]interface{}{"value": string(decoded)}, nil
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("payload is an empty JSON object, carrying no secret")
	}

	out := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		switch typed := v.(type) {
		case string:
			out[k] = typed
		case bool:
			out[k] = strconv.FormatBool(typed)
		case float64:
			// encoding/json decodes every JSON number as a float64. Render integers
			// without a decimal point so a stored port or id reads back as written.
			out[k] = strconv.FormatFloat(typed, 'f', -1, 64)
		case nil:
			return nil, fmt.Errorf("payload field %q is null", k)
		default:
			return nil, fmt.Errorf("payload field %q holds a nested object or array, which a key/value credential cannot carry; store it as its own secret, or as a string", k)
		}
	}
	return out, nil
}

// signingCapabilityPayloadPrefix marks spec-config keys carried verbatim into a minted
// signing capability. What travels there means something only to the consumer — the
// OAuth client the key is registered to, a key id an authorization server selects on —
// so a producer copies it without interpreting it, rather than growing config keys for
// a protocol it does not speak.
const signingCapabilityPayloadPrefix = "payload."

// signingCapabilityPayloadFields collects the payload.* passthrough bag with its prefix
// stripped, for a capability on backend. It is shared by every driver that mints a
// signing capability. Values may be claim-templated, so one spec can front a different
// client and a different key per caller.
//
// A name the capability is built from is refused rather than dropped. Stripped of its
// prefix, it would land on the same key as the coordinate and, merged after it, replace
// it — sending the capability somewhere else, or spending a credential that is not the
// one the mint obtained. Silently ignoring it instead would leave an operator with a
// spec that reads as though it set something.
//
// client_id is required: the consumer names the client its assertion is for, and a
// producer only carries that name.
func signingCapabilityPayloadFields(config credential.Config, backend string, userClaims, agentClaims map[string]string, errPrefix string) (map[string]string, error) {
	reserved := remotesign.ReservedCapabilityKeys(backend)
	if reserved == nil {
		// Without the codec there is nothing to check the bag against, and letting it
		// through would let it overwrite coordinates unchecked.
		return nil, fmt.Errorf("%s: no signing capability codec for backend %q", errPrefix, backend)
	}
	out := map[string]string{}
	for k, v := range credential.GetPrefixed(config, signingCapabilityPayloadPrefix) {
		if _, ok := reserved[k]; ok {
			return nil, fmt.Errorf(
				"%s: %s%s is not allowed: %q is part of the signing capability this mint writes, and carrying one here would replace it",
				errPrefix, signingCapabilityPayloadPrefix, k, k)
		}
		resolved, err := resolveClaimTemplate(v, userClaims, agentClaims, signingCapabilityPayloadPrefix+k)
		if err != nil {
			return nil, err
		}
		out[k] = resolved
	}
	if out["client_id"] == "" {
		return nil, fmt.Errorf(
			"%s: a signing capability requires %sclient_id on the spec: the consumer names the client its assertion is for, and this driver only carries that name",
			errPrefix, signingCapabilityPayloadPrefix)
	}
	return out, nil
}

// signingCapabilityTTL is how long a capability whose credential lasts credTTL is
// cached. A credential issued with no expiry still gets a positive lifetime, since a
// zero would read as "static" and never refresh; and none outlives the spec's MaxTTL.
func signingCapabilityTTL(credTTL time.Duration, spec *credential.CredSpec) time.Duration {
	if credTTL <= 0 {
		credTTL = 1 * time.Hour
	}
	if spec.MaxTTL > 0 && credTTL > spec.MaxTTL {
		credTTL = spec.MaxTTL
	}
	return credTTL
}
