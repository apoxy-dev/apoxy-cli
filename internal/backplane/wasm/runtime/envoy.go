package runtime

import "google.golang.org/protobuf/types/known/structpb"

type AttributeKey string

func (k AttributeKey) String() string {
	return string(k)
}

const (
	// HTTP request attributes.
	RequestMethodAttr    AttributeKey = "request.method"
	RequestPathAttr      AttributeKey = "request.path"
	RequestHostAttr      AttributeKey = "request.host"
	RequestSchemeAttr    AttributeKey = "request.scheme"
	RequestProtocolAttr  AttributeKey = "request.protocol"
	RequestSizeAttr      AttributeKey = "request.size"
	RequestTotalSizeAttr AttributeKey = "request.total_size"

	// HTTP response attributes.
	ResponseCodeAttr        AttributeKey = "response.code"
	ResponseCodeDetailsAttr AttributeKey = "response.code_details"
	ResponseSizeAttr        AttributeKey = "response.size"
	ResponseTotalSizeAttr   AttributeKey = "response.total_size"

	// Downstream connection attributes.
	SourceAddressAttr             AttributeKey = "source.address"
	SourcePortAttr                AttributeKey = "source.port"
	DestinationAddressAttr        AttributeKey = "destination.address"
	DestinationPortAttr           AttributeKey = "destination.port"
	ConnectionIDAttr              AttributeKey = "connection.id"
	ConnectionMTLSAttr            AttributeKey = "connection.mtls"
	ConnectionServerNameAttr      AttributeKey = "connection.requested_server_name"
	ConnectionTLSVersionAttr      AttributeKey = "connection.tls_version"
	ConnectionSubjLocalCertAttr   AttributeKey = "connection.subject_local_certificate"
	ConnectionSubjPeerCertAttr    AttributeKey = "connection.subject_peer_certificate"
	ConnectionDNSSanLocalCertAttr AttributeKey = "connection.dns_san_local_certificate"
	ConnectionDNSSanPeerCertAttr  AttributeKey = "connection.dns_san_peer_certificate"

	// Upstream connection attributes.
	UpstreamAddressAttr         AttributeKey = "upstream.address"
	UpstreamPortAttr            AttributeKey = "upstream.port"
	UpstreamTLSVersionAttr      AttributeKey = "upstream.tls_version"
	UpstreamSubjLocalCertAttr   AttributeKey = "upstream.subject_local_certificate"
	UpstreamSubjPeerCertAttr    AttributeKey = "upstream.subject_peer_certificate"
	UpstreamDNSSanLocalCertAttr AttributeKey = "upstream.dns_san_local_certificate"
	UpstreamDNSSanPeerCertAttr  AttributeKey = "upstream.dns_san_peer_certificate"
	UpstreamLocalAddressAttr    AttributeKey = "upstream.local_address"

	// Metadata keys.
	ApoxyMetadataNamespace    = "apoxy.io"
	ApoxyMetadataFunction     = "func"
	ApoxyMetadataFunctionName = "name"
	ApoxyMetadataFunctionPath = "path"
)

type PsuedoHeaderKey string

const (
	RequestPath   PsuedoHeaderKey = ":path"
	RequestHost   PsuedoHeaderKey = ":authority"
	RequestScheme PsuedoHeaderKey = ":scheme"
	RequestMethod PsuedoHeaderKey = ":method"

	ResponseStatus PsuedoHeaderKey = ":status"
)

func attrValue[T any](attrs map[string]*structpb.Struct, key AttributeKey) (*T, bool) {
	for _, attr := range attrs {
		if v := attr.Fields[key.String()]; v != nil {
			lv, ok := v.AsInterface().(T)
			if !ok {
				return nil, false
			}
			return &lv, true
		}
	}
	return nil, false
}
