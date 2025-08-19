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
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/conforma/cli/internal/applicationsnapshot"
)

// mockVSARetriever implements VSARetriever for testing
type mockVSARetriever struct {
	mock.Mock
}

func (m *mockVSARetriever) RetrieveVSA(ctx context.Context, imageDigest string) ([]VSARecord, error) {
	args := m.Called(ctx, imageDigest)
	return args.Get(0).([]VSARecord), args.Error(1)
}

func TestNewVSAExpirationChecker(t *testing.T) {
	retriever := &mockVSARetriever{}
	threshold := 24 * time.Hour

	checker := NewVSAExpirationChecker(retriever, threshold)

	assert.NotNil(t, checker)
	assert.Equal(t, retriever, checker.retriever)
	assert.Equal(t, threshold, checker.threshold)
}

func TestCheckVSAExpiration_EmptyDigest(t *testing.T) {
	retriever := &mockVSARetriever{}
	checker := NewVSAExpirationChecker(retriever, 24*time.Hour)

	result, err := checker.CheckVSAExpiration(context.Background(), "")

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "image digest cannot be empty")
}

func TestCheckVSAExpiration_NoVSARecords(t *testing.T) {
	retriever := &mockVSARetriever{}
	checker := NewVSAExpirationChecker(retriever, 24*time.Hour)
	digest := "sha256:abc123"

	retriever.On("RetrieveVSA", mock.Anything, digest).Return([]VSARecord{}, nil)

	result, err := checker.CheckVSAExpiration(context.Background(), digest)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, applicationsnapshot.VSAStatusMissing, result.Status)
	assert.Equal(t, "No VSA found in Rekor", result.Message)
	retriever.AssertExpectations(t)
}

func TestCheckVSAExpiration_FreshVSA(t *testing.T) {
	retriever := &mockVSARetriever{}
	threshold := 24 * time.Hour
	checker := NewVSAExpirationChecker(retriever, threshold)
	digest := "sha256:abc123"

	// Create a fresh VSA record (10 minutes old)
	freshTime := time.Now().Add(-10 * time.Minute).Unix()
	vsaRecord := VSARecord{
		IntegratedTime: freshTime,
		LogIndex:       123,
		LogID:          "test-log-id",
	}

	retriever.On("RetrieveVSA", mock.Anything, digest).Return([]VSARecord{vsaRecord}, nil)

	result, err := checker.CheckVSAExpiration(context.Background(), digest)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, applicationsnapshot.VSAStatusFresh, result.Status)
	assert.NotNil(t, result.Timestamp)
	assert.Contains(t, result.Message, "VSA is fresh")
	retriever.AssertExpectations(t)
}

func TestCheckVSAExpiration_ExpiredVSA(t *testing.T) {
	retriever := &mockVSARetriever{}
	threshold := 1 * time.Hour
	checker := NewVSAExpirationChecker(retriever, threshold)
	digest := "sha256:abc123"

	// Create an expired VSA record (2 hours old)
	expiredTime := time.Now().Add(-2 * time.Hour).Unix()
	vsaRecord := VSARecord{
		IntegratedTime: expiredTime,
		LogIndex:       123,
		LogID:          "test-log-id",
	}

	retriever.On("RetrieveVSA", mock.Anything, digest).Return([]VSARecord{vsaRecord}, nil)

	result, err := checker.CheckVSAExpiration(context.Background(), digest)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, applicationsnapshot.VSAStatusExpired, result.Status)
	assert.NotNil(t, result.Timestamp)
	assert.NotNil(t, result.ExpirationAge)
	assert.Contains(t, result.Message, "VSA is expired")
	retriever.AssertExpectations(t)
}

func TestCheckVSAExpiration_MultipleRecords_MostRecentUsed(t *testing.T) {
	retriever := &mockVSARetriever{}
	threshold := 1 * time.Hour
	checker := NewVSAExpirationChecker(retriever, threshold)
	digest := "sha256:abc123"

	// Create multiple VSA records with different timestamps
	oldTime := time.Now().Add(-3 * time.Hour).Unix()
	recentTime := time.Now().Add(-30 * time.Minute).Unix() // Fresh (within threshold)

	vsaRecords := []VSARecord{
		{
			IntegratedTime: oldTime,
			LogIndex:       100,
			LogID:          "old-log-id",
		},
		{
			IntegratedTime: recentTime,
			LogIndex:       200,
			LogID:          "recent-log-id",
		},
	}

	retriever.On("RetrieveVSA", mock.Anything, digest).Return(vsaRecords, nil)

	result, err := checker.CheckVSAExpiration(context.Background(), digest)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, applicationsnapshot.VSAStatusFresh, result.Status)
	assert.NotNil(t, result.Timestamp)

	// Should use the most recent timestamp
	expectedTime := time.Unix(recentTime, 0).UTC()
	assert.Equal(t, expectedTime, *result.Timestamp)

	retriever.AssertExpectations(t)
}

func TestCheckVSAExpiration_VSAPredicateTimestamp(t *testing.T) {
	retriever := &mockVSARetriever{}
	threshold := 1 * time.Hour
	checker := NewVSAExpirationChecker(retriever, threshold)
	digest := "sha256:abc123"

	// Create VSA record with attestation data containing timestamp
	vsaTimestamp := time.Now().Add(-30 * time.Minute).Format(time.RFC3339)
	attestationData := struct {
		Predicate struct {
			Timestamp string `json:"timestamp"`
		} `json:"predicate"`
	}{
		Predicate: struct {
			Timestamp string `json:"timestamp"`
		}{
			Timestamp: vsaTimestamp,
		},
	}

	attestationJSON, _ := json.Marshal(attestationData)
	encodedAttestation := base64.StdEncoding.EncodeToString(attestationJSON)

	vsaRecord := VSARecord{
		IntegratedTime: 0, // No integrated time, should fallback to attestation data
		LogIndex:       123,
		LogID:          "test-log-id",
		Attestation: &models.LogEntryAnonAttestation{
			Data: strfmt.Base64(encodedAttestation),
		},
	}

	retriever.On("RetrieveVSA", mock.Anything, digest).Return([]VSARecord{vsaRecord}, nil)

	result, err := checker.CheckVSAExpiration(context.Background(), digest)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, applicationsnapshot.VSAStatusFresh, result.Status)
	assert.NotNil(t, result.Timestamp)
	retriever.AssertExpectations(t)
}

func TestCheckMultipleVSAExpiration(t *testing.T) {
	retriever := &mockVSARetriever{}
	threshold := 1 * time.Hour
	checker := NewVSAExpirationChecker(retriever, threshold)

	digest1 := "sha256:abc123"
	digest2 := "sha256:def456"
	digests := []string{digest1, digest2}

	// Setup expectations
	freshTime := time.Now().Add(-30 * time.Minute).Unix()
	expiredTime := time.Now().Add(-2 * time.Hour).Unix()

	retriever.On("RetrieveVSA", mock.Anything, digest1).Return([]VSARecord{
		{IntegratedTime: freshTime, LogIndex: 100, LogID: "log1"},
	}, nil)

	retriever.On("RetrieveVSA", mock.Anything, digest2).Return([]VSARecord{
		{IntegratedTime: expiredTime, LogIndex: 200, LogID: "log2"},
	}, nil)

	results, err := checker.CheckMultipleVSAExpiration(context.Background(), digests)

	require.NoError(t, err)
	assert.Len(t, results, 2)

	assert.Equal(t, applicationsnapshot.VSAStatusFresh, results[digest1].Status)
	assert.Equal(t, applicationsnapshot.VSAStatusExpired, results[digest2].Status)

	retriever.AssertExpectations(t)
}

func TestExtractTimestampFromVSA_IntegratedTime(t *testing.T) {
	retriever := &mockVSARetriever{}
	checker := NewVSAExpirationChecker(retriever, 24*time.Hour)

	expectedTime := time.Now().Add(-1 * time.Hour)
	record := VSARecord{
		IntegratedTime: expectedTime.Unix(),
	}

	timestamp, err := checker.extractTimestampFromVSA(record)

	require.NoError(t, err)
	assert.NotNil(t, timestamp)
	assert.Equal(t, expectedTime.UTC().Truncate(time.Second), timestamp.Truncate(time.Second))
}

func TestExtractTimestampFromVSA_AttestationData(t *testing.T) {
	retriever := &mockVSARetriever{}
	checker := NewVSAExpirationChecker(retriever, 24*time.Hour)

	vsaTimestamp := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	attestationData := struct {
		Predicate struct {
			Timestamp string `json:"timestamp"`
		} `json:"predicate"`
	}{
		Predicate: struct {
			Timestamp string `json:"timestamp"`
		}{
			Timestamp: vsaTimestamp,
		},
	}

	attestationJSON, _ := json.Marshal(attestationData)
	encodedAttestation := base64.StdEncoding.EncodeToString(attestationJSON)

	record := VSARecord{
		IntegratedTime: 0, // No integrated time
		Attestation: &models.LogEntryAnonAttestation{
			Data: strfmt.Base64(encodedAttestation),
		},
	}

	timestamp, err := checker.extractTimestampFromVSA(record)

	require.NoError(t, err)
	assert.NotNil(t, timestamp)

	expectedTime, _ := time.Parse(time.RFC3339, vsaTimestamp)
	assert.Equal(t, expectedTime.UTC(), *timestamp)
}

func TestExtractTimestampFromVSA_NoTimestamp(t *testing.T) {
	retriever := &mockVSARetriever{}
	checker := NewVSAExpirationChecker(retriever, 24*time.Hour)

	record := VSARecord{
		IntegratedTime: 0,
		Attestation:    nil,
	}

	timestamp, err := checker.extractTimestampFromVSA(record)

	assert.Nil(t, timestamp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no timestamp available")
}
