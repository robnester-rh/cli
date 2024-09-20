package cache

import "sync"

type PolicyCache struct {
    Data sync.Map
}

func NewPolicyCache() *PolicyCache {
	return &PolicyCache{}
}

func (c *PolicyCache) Get(key string) (string, bool) {
    value, ok := c.Data.Load(key)
    if !ok {
        return "", false
    }
    strValue, ok := value.(string)
    if !ok {
        return "", false
    }
    return strValue, true
}