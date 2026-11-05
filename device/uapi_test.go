/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func randHeaderProtectionKey(t *testing.T) string {
	t.Helper()
	var key HeaderCipherKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key[:])
}

func TestHeaderProtectionPaddingValidation(t *testing.T) {
	key := randHeaderProtectionKey(t)

	testCases := []struct {
		name    string
		cfg     []string
		wantErr string
	}{
		{
			name: "no header protection, no padding",
			cfg:  []string{"s1", "0", "s2", "0", "s3", "0", "s4", "0"},
		},
		{
			name: "minimal padding",
			cfg:  []string{"header_protection_key", key, "s1", "12", "s2", "12", "s3", "12", "s4", "12"},
		},
		{
			name:    "s1 too small",
			cfg:     []string{"header_protection_key", key, "s1", "11", "s2", "12", "s3", "12", "s4", "12"},
			wantErr: "S1 must be at least 12 to use header protection, got 11",
		},
		{
			name:    "s2 too small",
			cfg:     []string{"header_protection_key", key, "s1", "12", "s2", "0", "s3", "12", "s4", "12"},
			wantErr: "S2 must be at least 12 to use header protection, got 0",
		},
		{
			name:    "s3 too small",
			cfg:     []string{"header_protection_key", key, "s1", "12", "s2", "12", "s3", "5", "s4", "12"},
			wantErr: "S3 must be at least 12 to use header protection, got 5",
		},
		{
			name:    "s4 too small",
			cfg:     []string{"header_protection_key", key, "s1", "12", "s2", "12", "s3", "12", "s4", "0"},
			wantErr: "S4 must be at least 12 to use header protection, got 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			device := randDevice(t)
			defer device.Close()

			err := device.IpcSet(uapiCfg(tc.cfg...))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}
