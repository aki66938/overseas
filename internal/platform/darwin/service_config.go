package darwin

import (
	"bytes"
	"corp.example/overseas-access-gateway/internal/accessmodel"
	"encoding/json"
	"errors"
	"io"
)

const (
	InstallDirectory   = "/Library/Application Support/RegenBioAccess"
	StateDirectory     = InstallDirectory + "/state"
	ServiceConfigPath  = InstallDirectory + "/service.json"
	CorePath           = InstallDirectory + "/sing-box"
	RenderedConfigPath = StateDirectory + "/sing-box.json"
	ServicePath        = InstallDirectory + "/regen-access-service"
	PinnedCoreSHA256   = "5b75c1dec19488675f725adc7a6e3a7301a553117af835dc47669b1fa918976b"
)

type ServiceConfig struct {
	SchemaVersion int                `json:"schema_version"`
	OwnerUID      int                `json:"owner_uid"`
	CoreSHA256    string             `json:"core_sha256"`
	Policy        accessmodel.Policy `json:"policy"`
}

func ParseServiceConfig(data []byte) (ServiceConfig, error) {
	var c ServiceConfig
	if len(data) > 65536 {
		return c, errors.New("service configuration too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	if c.SchemaVersion != 1 || c.OwnerUID < 501 || uint64(c.OwnerUID) > 2147483647 || c.CoreSHA256 != PinnedCoreSHA256 || c.Policy.SchemaVersion != 2 {
		return c, errors.New("unsupported service configuration")
	}
	if err := accessmodel.Validate(c.Policy); err != nil {
		return c, err
	}
	return c, nil
}
