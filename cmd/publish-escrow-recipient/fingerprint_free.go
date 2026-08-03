//go:build !enterprise

package main

// В open-core код кастодии не компилируется, поэтому посчитать отпечаток нечем.
func derivedFingerprint(string) (string, bool, error) { return "", false, nil }
