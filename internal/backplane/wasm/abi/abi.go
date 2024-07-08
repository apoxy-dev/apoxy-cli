package abi

type Request struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Proto      string            `json:"proto"`
	ProtoMajor int               `json:"proto_major"`
	ProtoMinor int               `json:"proto_minor"`
	Header     map[string]string `json:"header"`
	Host       string            `json:"host"`
	RemoteAddr string            `json:"remote_addr"`
	ContentLen int               `json:"content_len"`

	Body []byte `json:"-"`
}

type Response struct {
	StatusCode int               `json:"status_code"`
	Header     map[string]string `json:"header"`
	ContentLen int               `json:"content_len"`

	Body []byte `json:"-"`
}
