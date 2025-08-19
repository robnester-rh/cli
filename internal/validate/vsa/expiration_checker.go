// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/conforma/cli/internal/applicationsnapshot"
)

// Use types from applicationsnapshot package to avoid circular imports
type VSAExpirationStatus = applicationsnapshot.VSAExpirationStatus
type VSAExpirationResult = applicationsnapshot.VSAExpirationResult

const (
	VSAStatusFresh   = applicationsnapshot.VSAStatusFresh
	VSAStatusExpired = applicationsnapshot.VSAStatusExpired
	VSAStatusMissing = applicationsnapshot.VSAStatusMissing
)

// VSAExpirationChecker handles checking VSA expiration for components
type VSAExpirationChecker struct {
	retriever VSARetriever
	threshold time.Duration
}

// NewVSAExpirationChecker creates a new VSA expiration checker
func NewVSAExpirationChecker(retriever VSARetriever, threshold time.Duration) *VSAExpirationChecker {
	return &VSAExpirationChecker{
		retriever: retriever,
		threshold: threshold,
	}
}

// CheckVSAExpiration checks if a VSA exists for the given image digest and whether it's expired
func (c *VSAExpirationChecker) CheckVSAExpiration(ctx context.Context, imageDigest string) (*VSAExpirationResult, error) {
	if imageDigest == "" {
		return nil, fmt.Errorf("image digest cannot be empty")
	}

	log.Debugf("Checking VSA expiration for image digest: %s", imageDigest)

	// Retrieve VSA records from Rekor
	vsaRecords, err := c.retriever.RetrieveVSA(ctx, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve VSA records: %w", err)
	}

	if len(vsaRecords) == 0 {
		log.Debugf("No VSA records found for image digest: %s", imageDigest)
		return &VSAExpirationResult{
			Status:  VSAStatusMissing,
			Message: "No VSA found in Rekor",
		}, nil
	}

	// Find the most recent VSA record
	var mostRecentRecord *VSARecord
	var mostRecentTime time.Time

	for i, record := range vsaRecords {
		// Extract timestamp from the VSA record
		timestamp, err := c.extractTimestampFromVSA(record)
		if err != nil {
			log.Warnf("Failed to extract timestamp from VSA record %d: %v", i, err)
			continue
		}

		if mostRecentRecord == nil || timestamp.After(mostRecentTime) {
			mostRecentRecord = &record
			mostRecentTime = *timestamp
		}
	}

	if mostRecentRecord == nil {
		return &VSAExpirationResult{
			Status:  VSAStatusMissing,
			Message: "No valid VSA records with timestamps found",
		}, nil
	}

	// Check if the VSA is expired
	now := time.Now().UTC()
	age := now.Sub(mostRecentTime)

	if age > c.threshold {
		log.Debugf("VSA is expired: age=%v, threshold=%v", age, c.threshold)
		return &VSAExpirationResult{
			Status:        VSAStatusExpired,
			Timestamp:     &mostRecentTime,
			ExpirationAge: &age,
			Message:       fmt.Sprintf("VSA is expired (age: %v, threshold: %v)", age, c.threshold),
		}, nil
	}

	log.Debugf("VSA is fresh: age=%v, threshold=%v", age, c.threshold)
	return &VSAExpirationResult{
		Status:    VSAStatusFresh,
		Timestamp: &mostRecentTime,
		Message:   fmt.Sprintf("VSA is fresh (age: %v)", age),
	}, nil
}

// extractTimestampFromVSA extracts the timestamp from a VSA record
func (c *VSAExpirationChecker) extractTimestampFromVSA(record VSARecord) (*time.Time, error) {
	// First try to get timestamp from the Rekor integrated time
	if record.IntegratedTime > 0 {
		timestamp := time.Unix(record.IntegratedTime, 0).UTC()
		log.Debugf("Using Rekor integrated time: %v", timestamp)
		return &timestamp, nil
	}

	// If no integrated time, try to extract from the VSA attestation data
	if record.Attestation != nil && record.Attestation.Data != nil {
		attestationData, err := base64.StdEncoding.DecodeString(string(record.Attestation.Data))
		if err != nil {
			return nil, fmt.Errorf("failed to decode attestation data: %w", err)
		}

		// Parse the attestation to extract the VSA predicate timestamp
		var attestation struct {
			Predicate struct {
				Timestamp string `json:"timestamp"`
			} `json:"predicate"`
		}

		if err := json.Unmarshal(attestationData, &attestation); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attestation: %w", err)
		}

		if attestation.Predicate.Timestamp == "" {
			return nil, fmt.Errorf("no timestamp found in VSA predicate")
		}

		timestamp, err := time.Parse(time.RFC3339, attestation.Predicate.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VSA timestamp: %w", err)
		}

		timestampUTC := timestamp.UTC()
		log.Debugf("Using VSA predicate timestamp: %v", timestampUTC)
		return &timestampUTC, nil
	}

	return nil, fmt.Errorf("no timestamp available in VSA record")
}

// CheckMultipleVSAExpiration checks VSA expiration for multiple image digests
func (c *VSAExpirationChecker) CheckMultipleVSAExpiration(ctx context.Context, imageDigests []string) (map[string]*VSAExpirationResult, error) {
	results := make(map[string]*VSAExpirationResult)

	for _, digest := range imageDigests {
		result, err := c.CheckVSAExpiration(ctx, digest)
		if err != nil {
			log.Warnf("Failed to check VSA expiration for digest %s: %v", digest, err)
			results[digest] = &VSAExpirationResult{
				Status:  VSAStatusMissing,
				Message: fmt.Sprintf("Error checking VSA: %v", err),
			}
		} else {
			results[digest] = result
		}
	}

	return results, nil
}
