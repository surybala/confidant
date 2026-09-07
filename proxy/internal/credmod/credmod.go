// SPDX-License-Identifier: Apache-2.0

// Package credmod implements the credential modules (broker-core.md §04a):
// one interface, several implementations, dispatched by policy.Credential.Kind.
//
// The scheme comes only from stored policy (invariant I-B2). Phase 1 implements
// the Static module (bearer/header/query/basic); SigV4 and OAuth2 are registered
// but not yet implemented, so their use fails closed rather than silently
// sending an unauthenticated request.
package credmod

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/surybala/confidant/proxy/internal/policy"
)

// ErrNotImplemented is returned by modules that are registered but not built yet.
var ErrNotImplemented = fmt.Errorf("credential module not implemented")

// Module attaches a credential to an outbound request. It returns the name of a
// response/request header the pipeline should scrub from the response ("" if
// none, e.g. query injection).
type Module interface {
	Apply(req *http.Request, cred policy.Credential, secret []byte) (scrubHeader string, err error)
}

// Registry maps a credential kind to its module.
type Registry map[string]Module

// Default returns the Phase-1 registry.
func Default() Registry {
	return Registry{
		"static": Static{},
		"sigv4":  notImplemented{},
		"oauth2": notImplemented{},
	}
}

// Get returns the module for a kind, or false.
func (r Registry) Get(kind string) (Module, bool) {
	m, ok := r[kind]
	return m, ok
}

// IsImplemented reports whether m is a real credential module rather than a
// registered fail-closed stub.
func IsImplemented(m Module) bool {
	_, stub := m.(notImplemented)
	return !stub
}

// Static injects a static string credential per cred.Inject.
type Static struct{}

// Apply implements Module.
func (Static) Apply(req *http.Request, cred policy.Credential, secret []byte) (string, error) {
	in := cred.Inject
	switch in.Type {
	case "", "header":
		name := in.Name
		if name == "" {
			name = "Authorization"
		}
		req.Header.Set(name, expand(in.Template, secret))
		return name, nil
	case "basic":
		// secret is expected to be "user:pass"; encode as HTTP Basic.
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(secret))
		return "Authorization", nil
	case "query":
		if in.Name == "" {
			return "", fmt.Errorf("query injection requires a name")
		}
		q := req.URL.Query()
		q.Set(in.Name, expand(in.Template, secret))
		req.URL.RawQuery = q.Encode()
		return "", nil // nothing to scrub from response headers
	default:
		return "", fmt.Errorf("unknown inject type %q", in.Type)
	}
}

// expand substitutes {secret} in the template (default "{secret}").
func expand(tmpl string, secret []byte) string {
	if tmpl == "" {
		tmpl = "{secret}"
	}
	return strings.ReplaceAll(tmpl, "{secret}", string(secret))
}

type notImplemented struct{}

func (notImplemented) Apply(*http.Request, policy.Credential, []byte) (string, error) {
	return "", ErrNotImplemented
}
