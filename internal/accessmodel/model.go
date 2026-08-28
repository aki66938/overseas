package accessmodel

type Policy struct {
	SchemaVersion    int           `yaml:"schema_version" json:"schema_version"`
	Mode             string        `yaml:"mode" json:"mode"`
	Nodes            []Node        `yaml:"nodes" json:"nodes"`
	CorporateCIDRs   []string      `yaml:"corporate_cidrs" json:"corporate_cidrs"`
	CorporateDNS     []string      `yaml:"corporate_dns" json:"corporate_dns"`
	InternalSuffixes []string      `yaml:"internal_suffixes" json:"internal_suffixes"`
	BlockUDP         bool          `yaml:"block_udp" json:"block_udp"`
	BlockQUIC        bool          `yaml:"block_quic" json:"block_quic"`
	Credential       CredentialRef `yaml:"credential" json:"credential"`
}

type Node struct {
	ID       string `yaml:"id" json:"id"`
	Address  string `yaml:"address" json:"address"`
	Port     uint16 `yaml:"port" json:"port"`
	Priority int    `yaml:"priority" json:"priority"`
}

type CredentialRef struct {
	Kind string `yaml:"kind" json:"kind"`
	Path string `yaml:"path" json:"path"`
}

type RoutePolicy string

const (
	RoutePolicyDirect RoutePolicy = "direct"
	RoutePolicyTunnel RoutePolicy = "tunnel"
	RoutePolicyReject RoutePolicy = "reject"
)

type ConnectionState string

const (
	StateDisconnected ConnectionState = "disconnected"
	StateConnecting   ConnectionState = "connecting"
	StateConnected    ConnectionState = "connected"
	StateFailed       ConnectionState = "failed"
)
