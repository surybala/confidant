// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

func TestGCPSetupGuideNarrowsWIFPolicy(t *testing.T) {
	b, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	if strings.Contains(readme, "workloadIdentityPools/confidant-pool/*") {
		t.Fatal("README must not grant service-account impersonation to the whole WIF pool")
	}
	for _, want := range []string{
		"attribute.image_digest=assertion.submods.container.image_digest",
		"assertion.submods.container.image_reference",
		"assertion.submods.gce.project_number",
		"assertion.google_service_accounts",
		"assertion.submods.container.env['KMS_KEY']",
		"assertion.submods.container.env['WIF_AUDIENCE']",
		`export IMAGE_DIGEST="${IMAGE_REF##*@}"`,
		"/attribute.image_digest/${IMAGE_DIGEST}",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README WIF policy is missing %q", want)
		}
	}
}
