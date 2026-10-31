package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef makeString(const char *value) {
	return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static OSStatus readPassword(const char *service, const char *account, const UInt8 **bytes, CFIndex *length) {
	CFStringRef serviceValue = makeString(service);
	CFStringRef accountValue = makeString(account);
	const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit };
	const void *values[] = { kSecClassGenericPassword, serviceValue, accountValue, kCFBooleanTrue, kSecMatchLimitOne };
	CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	if (status == errSecSuccess) {
		CFDataRef data = (CFDataRef)result;
		*length = CFDataGetLength(data);
		UInt8 *copy = malloc(*length);
		if (*length > 0 && copy == NULL) {
			status = -1;
		} else {
			if (*length > 0) memcpy(copy, CFDataGetBytePtr(data), *length);
			*bytes = copy;
		}
		CFRelease(data);
	}
	CFRelease(query);
	CFRelease(serviceValue);
	CFRelease(accountValue);
	return status;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func lookupKeychain(service, account string) ([]byte, error) {
	serviceValue := C.CString(service)
	defer C.free(unsafe.Pointer(serviceValue))
	accountValue := C.CString(account)
	defer C.free(unsafe.Pointer(accountValue))
	var bytes *C.UInt8
	var length C.CFIndex
	status := C.readPassword(serviceValue, accountValue, (**C.UInt8)(unsafe.Pointer(&bytes)), &length)
	if status == C.errSecItemNotFound {
		return nil, errKeyNotFound
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("SecItemCopyMatching returned status %d", int(status))
	}
	defer C.free(unsafe.Pointer(bytes))
	return C.GoBytes(unsafe.Pointer(bytes), C.int(length)), nil
}
