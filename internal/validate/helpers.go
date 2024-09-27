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

	"github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

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

// PreProcessPolicy takes a policy.Options object and pre-loads the cache by downloading the policy.
// It returns a new policy object that has policy URLs which are pinned along with a cache object.
func PreProcessPolicy(ctx context.Context, policyOptions policy.Options) (policy.Policy, *cache.PolicyCache, error) {
	var policyCache *cache.PolicyCache
	pinnedPolicyUrls := map[string][]string{}
	policyCache, ok := cache.PolicyCacheFromContext(ctx)
	if !ok {
		log.Debugf("No cache in context, creating new one")
		policyCache = cache.NewPolicyCache()
	} else {
		log.Debugf("Cache found in context")
	}

	p, err := policy.NewPolicy(ctx, policyOptions)
	if err != nil {
		return nil, nil, err
	}

	sources := p.Spec().Sources
	for i, sourceGroup := range sources {
		log.Debugf("Fetching policy source group '%+v'\n", sourceGroup.Name)
		policySources, err := source.FetchPolicySources(sourceGroup)
		if err != nil {
			log.Debugf("Failed to fetch policy source group '%s'!\n", sourceGroup.Name)
			return nil, nil, err
		}

		fs := utils.FS(ctx)
		dir, err := utils.CreateWorkDir(fs)
		policyCache.Set("workDir", dir, err)
		if err != nil {
			log.Debug("Failed to create work dir!")
			return nil, nil, err
		}

		for _, policySource := range policySources {
			if strings.HasPrefix(policySource.PolicyUrl(), "data:") {
				continue
			}

			destDir, err := policySource.GetPolicy(ctx, dir, false)
			if err != nil {
				log.Debugf("Unable to download source from %s!", policySource.PolicyUrl())
				return nil, nil, err
			}
			log.Debugf("Downloaded policy source from %s to %s\n", policySource.PolicyUrl(), destDir)

			url := policySource.PolicyUrl()

			if _, found := policyCache.Get(policySource.PolicyUrl()); !found {
				log.Debugf("Cache miss for: %s, adding to cache", url)
				policyCache.Set(url, destDir, nil)
				pinnedPolicyUrls[policySource.Subdir()] = append(pinnedPolicyUrls[policySource.Subdir()], url)
				log.Debugf("Added %s to the pinnedPolicyUrls in \"%s\"", url, policySource.Subdir())
			} else {
				log.Debugf("Cache hit for: %s", url)
			}
		}

		sources[i] = v1alpha1.Source{
			Name:           sourceGroup.Name,
			Policy:         urls(policySources, source.PolicyKind),
			Data:           urls(policySources, source.DataKind),
			RuleData:       sourceGroup.RuleData,
			Config:         sourceGroup.Config,
			VolatileConfig: sourceGroup.VolatileConfig,
		}
	}

	return p, policyCache, err
}

func urls(s []source.PolicySource, kind source.PolicyType) []string {
	ret := make([]string, 0, len(s))
	for _, u := range s {
		if u.Type() == kind {
			ret = append(ret, u.PolicyUrl())
		}
	}

	return ret
}
