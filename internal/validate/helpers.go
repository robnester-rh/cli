// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"context"
	"fmt"
	"strings"

	"github.com/enterprise-contract/go-gather/metadata"
	gitMetadata "github.com/enterprise-contract/go-gather/metadata/git"
	ociMetadata "github.com/enterprise-contract/go-gather/metadata/oci"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"sigs.k8s.io/yaml"

	"github.com/enterprise-contract/ec-cli/internal/cache"
	"github.com/enterprise-contract/ec-cli/internal/policy"
	"github.com/enterprise-contract/ec-cli/internal/policy/source"
	"github.com/enterprise-contract/ec-cli/internal/utils"
)

// Determine policyConfig
func GetPolicyConfig(ctx context.Context, policyConfiguration string) (string, error) {
	// If policyConfiguration is not detected as a file and is detected as a git URL,
	// or if policyConfiguration is an https URL try to download a config file from
	// the provided source. If successful we read its contents and return it.
	if source.SourceIsGit(policyConfiguration) && !source.SourceIsFile(policyConfiguration) || source.SourceIsHttp(policyConfiguration) {
		log.Debugf("Fetching policy config from url: %s", policyConfiguration)

		// Create a temporary dir to download the config. This is separate from the workDir usd
		// later for downloading policy sources, but it doesn't matter because this dir is not
		// used again once the config file has been read.
		fs := utils.FS(ctx)
		tmpDir, err := utils.CreateWorkDir(fs)
		if err != nil {
			return "", err
		}
		defer utils.CleanupWorkDir(fs, tmpDir)

		// Git download and find a suitable config file
		configFile, err := source.GoGetterDownload(ctx, tmpDir, policyConfiguration)
		if err != nil {
			return "", err
		}
		log.Debugf("Loading %s as policy configuration", configFile)
		return ReadFile(ctx, configFile)
	} else if source.SourceIsFile(policyConfiguration) && utils.HasJsonOrYamlExt(policyConfiguration) {
		// If policyConfiguration is detected as a file and it has a json or yaml extension,
		// we read its contents and return it.
		log.Debugf("Loading %s as policy configuration", policyConfiguration)
		return ReadFile(ctx, policyConfiguration)
	}

	// If policyConfiguration is not a file path, git url, or https url,
	// we assume it's a string and return it as is.
	return policyConfiguration, nil
}

// Read file from the workspace and return its contents.
func ReadFile(ctx context.Context, fileName string) (string, error) {
	fs := utils.FS(ctx)
	fileBytes, err := afero.ReadFile(fs, fileName)
	if err != nil {
		return "", err
	}
	// Check for empty file as that would cause a false "success"
	if len(fileBytes) == 0 {
		err := fmt.Errorf("file %s is empty", fileName)
		return "", err
	}
	log.Debugf("Loaded %s", fileName)
	return string(fileBytes), nil
}

// downloadCache is a concurrent map used to cache downloaded files.

// PreProcessPolicy takes a policy object and pre-loads the cache by downloading the policy.
// It returns a new policy object that has policy URLs which are pinned along with a cache object.
func PreProcessPolicy(ctx context.Context, policyOptions policy.Options) (policy.Policy, *cache.PolicyCache, error) {
	pinnedPolicyUrls := map[string][]string{}
	cache := cache.NewPolicyCache()

	p, err := policy.NewPolicy(ctx, policyOptions)
	if err != nil {
		return nil, nil, err
	}

	for _, sourceGroup := range p.Spec().Sources {
		log.Debugf("Fetching policy source group '%+v'\n", sourceGroup.Name)
		policySources, err := source.FetchPolicySources(sourceGroup)
		if err != nil {
			log.Debugf("Failed to fetch policy source group '%s'!\n", sourceGroup.Name)
			return nil, nil, err
		}

		fs := utils.FS(ctx)
		dir, err := utils.CreateWorkDir(fs)
		if err != nil {
			log.Debug("Failed to create work dir!")
			return nil, nil, err
		}

		for _, policySource := range policySources {
			if !strings.HasPrefix(policySource.PolicyUrl(), "data:application/json;base64,") {
				destDir, metadata, err := policySource.GetPolicyWithMetadata(ctx, dir, false)
				if err != nil {
					log.Debugf("Unable to download source from %s!", policySource.PolicyUrl())
					return nil, nil, err
				}
				log.Debugf("Downloaded policy source from %s to %s\n", policySource.PolicyUrl(), destDir)
				pinnedURL, err := getPinnedUrl(policySource.PolicyUrl(), metadata)

				if err != nil {
					return nil, nil, err
				}
				cache.Data.Store(pinnedURL, destDir)

				pinnedPolicyUrls[policySource.Subdir()] = append(pinnedPolicyUrls[policySource.Subdir()], pinnedURL)
				log.Debugf("Added %s to the pinnedPolicyUrls in \"%s\"", pinnedURL, policySource.Subdir())
			}
		}
	}

	policyRef := policyOptions.PolicyRef

	var result map[string]interface{}
	err = yaml.Unmarshal([]byte(policyRef), &result)
	if err != nil {
		return nil, nil, err
	}

	var sources []interface{}
	if spec, ok := result["spec"].(map[string]interface{}); ok {
		if s, ok := spec["sources"].([]interface{}); ok {
			sources = s
		}
	}
	if s, ok := result["sources"].([]interface{}); ok {
		sources = s
	}

	for _, source := range sources {
		sourceMap, ok := source.(map[string]interface{})
		if !ok {
			log.Debugf("skipping %+v: source item is not a map", sourceMap)
			continue
		}

		if len(pinnedPolicyUrls["policy"]) > 0 {
			sourceMap["policy"] = pinnedPolicyUrls["policy"]
		}

		if len(pinnedPolicyUrls["data"]) > 0 {
			sourceMap["data"] = pinnedPolicyUrls["data"]
		}
	}

	if len(result) > 0 {
		policyConfigYaml, err := yaml.Marshal(result)
		if err != nil {
			return nil, nil, err
		}

		policyOptions.PolicyRef = string(policyConfigYaml)
		p, err = policy.NewPolicy(ctx, policyOptions)
		if err != nil {
			return nil, nil, err
		}
	}

	// TODO: WORK ON CACHE
	return p, cache, err
}

func getPinnedUrl(u string, m metadata.Metadata) (string, error) {
	if m == nil {
		return "", fmt.Errorf("metadata is nil")
	}

	if len(u) == 0 {
		return "", fmt.Errorf("url is empty")
	}

	switch t := m.(type) {
	case *gitMetadata.GitMetadata:
		url := strings.Split(strings.Split(u, "//")[0], "?")[0]
		path := strings.Split(u, "//")[1]
		url = fmt.Sprintf("%s?ref=%s", url, t.LatestCommit)
		if path != "" {
			url = fmt.Sprintf("%s//%s", url, path)
		}
		return url, nil
	case *ociMetadata.OCIMetadata:
		url := strings.Split(strings.Split(u, "//")[0], ":")[0]
		return fmt.Sprintf("%s@%s", url, t.Digest), nil
	default:
		return "", fmt.Errorf("unknown metadata type")
	}
}
