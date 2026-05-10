package utils

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	armorHeader    = "-----BEGIN GO-ENCRYPTOR FILE-----"
	armorFooter    = "-----END GO-ENCRYPTOR FILE-----"
	armorLineLen   = 64
	maxArmorSize   = 100 * 1024 * 1024 // 100 MB maximum plaintext size
)

func ArmorEncode(data []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(armorHeader + "\n\n")
	b64 := base64.StdEncoding.EncodeToString(data)
	for i := 0; i < len(b64); i += armorLineLen {
		end := i + armorLineLen
		if end > len(b64) {
			end = len(b64)
		}
		buf.WriteString(b64[i:end] + "\n")
	}
	buf.WriteString(armorFooter + "\n")
	return buf.Bytes()
}

func ArmorDecode(data []byte) ([]byte, error) {
	s := strings.TrimLeft(string(data), " \t\r\n")
	if !strings.HasPrefix(s, armorHeader) {
		return nil, errors.New("not armored data")
	}

	start := strings.Index(s, "\n\n")
	if start < 0 {
		start = strings.Index(s, "\n")
		if start < 0 {
			return nil, errors.New("invalid armor format")
		}
	}
	s = s[start:]

	end := strings.Index(s, armorFooter)
	if end < 0 {
		return nil, errors.New("invalid armor format: missing footer")
	}

	trailing := strings.TrimSpace(s[end+len(armorFooter):])
	if trailing != "" {
		return nil, errors.New("invalid armor format: trailing data after footer")
	}

	s = s[:end]

	var b64Buf bytes.Buffer
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b64Buf.WriteString(line)
	}

	b64Str := b64Buf.String()
	// Estimate decoded size: base64 uses 4 chars per 3 bytes.
	// Reject oversized input before decoding.
	maxB64Len := ((maxArmorSize + 2) / 3) * 4
	if len(b64Str) > maxB64Len {
		return nil, fmt.Errorf("armor data too large: %d bytes max", maxArmorSize)
	}

	decoded, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, fmt.Errorf("invalid armor base64: %w", err)
	}
	return decoded, nil
}

func IsArmored(data []byte) bool {
	return len(data) >= len(armorHeader) && string(data[:len(armorHeader)]) == armorHeader
}
