package httputil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// BenchmarkBuildHTTPClient_Concurrent drives one built client from many goroutines at
// once — a source's concurrent mints — and reports how many connections it had to open
// per 1000 requests alongside the usual cost per request.
//
// plain measures TCP reuse; tls also pays a handshake for every connection opened.
func BenchmarkBuildHTTPClient_Concurrent(b *testing.B) {
	for _, mode := range []string{"plain", "tls"} {
		b.Run(mode, func(b *testing.B) {
			srv, opened := countingServer(b, mode == "tls")
			var caPEM []byte
			if mode == "tls" {
				caPEM = serverCAPEM(srv)
			}
			client, err := BuildHTTPClient(caPEM, false, 0)
			require.NoError(b, err)
			defer client.CloseIdleConnections()
			require.NoError(b, drain(client, srv.URL))

			before := opened.Load()
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := drain(client, srv.URL); err != nil {
						b.Error(err)
						return
					}
				}
			})
			b.StopTimer()
			b.ReportMetric(float64(opened.Load()-before)*1000/float64(b.N), "conns/1k-req")
		})
	}
}
