package csvtoso

import (
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/mpkondrashin/tmdetect/pkg/apex"
)

type IsFunc func(string) bool

func DetectType(s string) (string, apex.ObjectType, error) {
	if govalidator.IsSHA1(s) {
		return s, apex.ObjectTypeSha1, nil
	}
	if govalidator.IsSHA256(s) {
		return s, apex.ObjectTypeSha256, nil
	}
	if s, ok := IsIP(s); ok {
		return s, apex.ObjectTypeIp, nil
	}
	if s, ok := IsDNSName(s); ok {
		return s, apex.ObjectTypeDomain, nil
	}
	if s, ok := IsURL(s); ok {
		return s, apex.ObjectTypeUrl, nil
	}
	return "", 0, apex.ErrUnknownObjectType
}

func IsIP(s string) (string, bool) {
	s = strings.ReplaceAll(s, "[.]", ".")
	if govalidator.IsIPv4(s) {
		return s, true
	}
	return "", false
}

func IsDNSName(s string) (string, bool) {
	s = strings.ReplaceAll(s, "[.]", ".")
	if !strings.ContainsRune(s, '.') {
		return "", false
	}
	return s, govalidator.IsDNSName(s)
}

func IsURL(s string) (string, bool) {
	if strings.HasPrefix(strings.ToLower(s), "hxxp") {
		s = "http" + s[4:]
	}
	if strings.HasPrefix(strings.ToLower(s), "http//") {
		return "", false
	}
	s = strings.ReplaceAll(s, "[.]", ".")
	if govalidator.IsEmail(s) {
		return "", false
	}
	if govalidator.IsURL(s) {
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			return s, true
		}
		return "https://" + s, true
	}
	return "", false
}
