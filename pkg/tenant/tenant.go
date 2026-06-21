package tenant

import "crypto/subtle"

type IDHash [32]byte

func ValidateTenant(memoryTenant, runtimeTenant IDHash) bool {
	return subtle.ConstantTimeCompare(memoryTenant[:], runtimeTenant[:]) == 1
}

func ValidateDomain(memoryDomain, runtimeDomain IDHash) bool {
	return subtle.ConstantTimeCompare(memoryDomain[:], runtimeDomain[:]) == 1
}
