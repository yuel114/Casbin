package main

import (
	"sync"
)

// CachedEnforcer wraps a standard Enforcer with a decision cache.
// All policy modifications automatically invalidate the cache.
type CachedEnforcer struct {
	enforcer *Enforcer
	cache    sync.Map // key: "sub|obj|act" -> bool
	mu       sync.RWMutex
}

// NewCachedEnforcer creates a new CachedEnforcer instance.
func NewCachedEnforcer(e *Enforcer) *CachedEnforcer {
	return &CachedEnforcer{
		enforcer: e,
	}
}

// Enforce checks authorization with caching.
func (c *CachedEnforcer) Enforce(sub, obj, act string) bool {
	key := sub + "|" + obj + "|" + act

	// Try read from cache first
	if val, ok := c.cache.Load(key); ok {
		return val.(bool)
	}

	// Cache miss - compute and store
	result := c.enforcer.Enforce(sub, obj, act)
	c.cache.Store(key, result)
	return result
}

// InvalidateCache clears all cached decisions.
func (c *CachedEnforcer) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = sync.Map{}
}

// AddPolicy adds a rule and invalidates cache.
func (c *CachedEnforcer) AddPolicy(params ...string) bool {
	result := c.enforcer.AddPolicy(params...)
	if result {
		c.InvalidateCache()
	}
	return result
}

// AddPolicies adds multiple rules and invalidates cache.
func (c *CachedEnforcer) AddPolicies(rules [][]string) bool {
	result := c.enforcer.AddPolicies(rules)
	if result {
		c.InvalidateCache()
	}
	return result
}

// RemovePolicy removes a rule and invalidates cache.
func (c *CachedEnforcer) RemovePolicy(params ...string) bool {
	result := c.enforcer.RemovePolicy(params...)
	if result {
		c.InvalidateCache()
	}
	return result
}

// RemovePolicies removes multiple rules and invalidates cache.
func (c *CachedEnforcer) RemovePolicies(rules [][]string) bool {
	result := c.enforcer.RemovePolicies(rules)
	if result {
		c.InvalidateCache()
	}
	return result
}

// UpdatePolicy updates a rule and invalidates cache.
func (c *CachedEnforcer) UpdatePolicy(oldPolicy, newPolicy []string) bool {
	result := c.enforcer.UpdatePolicy(oldPolicy, newPolicy)
	if result {
		c.InvalidateCache()
	}
	return result
}

// UpdatePolicies updates multiple rules and invalidates cache.
func (c *CachedEnforcer) UpdatePolicies(oldPolicies, newPolicies [][]string) bool {
	result := c.enforcer.UpdatePolicies(oldPolicies, newPolicies)
	if result {
		c.InvalidateCache()
	}
	return result
}

// RemoveFilteredPolicy removes rules by filter and invalidates cache.
func (c *CachedEnforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) bool {
	result := c.enforcer.RemoveFilteredPolicy(fieldIndex, fieldValues...)
	if result {
		c.InvalidateCache()
	}
	return result
}

// LoadPolicy reloads policies from adapter and invalidates cache.
func (c *CachedEnforcer) LoadPolicy() error {
	err := c.enforcer.LoadPolicy()
	if err == nil {
		c.InvalidateCache()
	}
	return err
}
