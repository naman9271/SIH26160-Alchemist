//go:build !linux

package xfrm

// NewRealProvider reports no provider where Linux XFRM Netlink is absent.
func NewRealProvider() Provider { return nil }
