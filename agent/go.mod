// confidant-agent — the local, secretless side.
//
// Runs a loopback forward proxy that tools point at. It recognizes credential
// refs in outbound requests to configured hosts and relays them to the broker
// over mTLS. It holds no long-lived secret and never calls an upstream API.
//
// A separate module from the proxy so each binary builds and runs standalone.
//
// See ../docs/local-agent.md
module github.com/surybala/confidant/agent

go 1.22
