//go:build windows

package snclient

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/bmatcuk/doublestar/v4"
	"golang.org/x/sys/windows/registry"
)

const registryQwordSize = 8

type registryRoot struct {
	hive       string
	key        registry.Key
	subkey     string
	normalized string
}

func (l *CheckRegistry) queryRegistry(ctx context.Context) ([]registryEntry, error) {
	entries := make([]registryEntry, 0)
	access := uint32(registry.READ) | l.registryViewAccess()

	for _, rawKey := range l.keys {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("registry scan canceled: %w", err)
		}

		root, err := parseRegistryRoot(rawKey)
		if err != nil {
			return nil, err
		}

		key, err := registry.OpenKey(root.key, root.subkey, access)
		if errors.Is(err, registry.ErrNotExist) {
			missingErr := l.addMissingRoot(&entries, root)
			if missingErr != nil {
				return nil, missingErr
			}

			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to open registry key %s: %w", root.normalized, err)
		}

		err = l.walkRegistryKey(ctx, key, root, root.normalized, 0, &entries)
		closeErr := key.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, fmt.Errorf("failed to close registry key %s: %w", root.normalized, closeErr)
		}
	}

	return entries, nil
}

func (l *CheckRegistry) walkRegistryKey(
	ctx context.Context,
	key registry.Key,
	root registryRoot,
	keyPath string,
	depth int64,
	entries *[]registryEntry,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("registry scan canceled: %w", err)
	}

	info, err := key.Stat()
	if err != nil {
		return fmt.Errorf("failed to read registry key information for %s: %w", keyPath, err)
	}

	written, age := registryKeyTimes(info)
	if len(l.values) == 0 {
		entry := &registryEntry{
			Kind:        "key",
			Hive:        root.hive,
			Path:        keyPath,
			Key:         keyPath,
			Name:        registryLeafName(keyPath),
			Exists:      true,
			Written:     written,
			Age:         age,
			SubkeyCount: info.SubKeyCount,
			ValueCount:  info.ValueCount,
		}
		appendErr := l.appendRegistryEntry(entries, entry)
		if appendErr != nil {
			return appendErr
		}
	} else {
		readErr := l.readRegistryValues(key, root.hive, keyPath, written, age, entries)
		if readErr != nil {
			return readErr
		}
	}

	if !l.recursive || (l.maxDepth >= 0 && depth >= l.maxDepth) {
		return nil
	}

	return l.walkRegistrySubkeys(ctx, key, root, keyPath, depth, entries)
}

func (l *CheckRegistry) walkRegistrySubkeys(
	ctx context.Context,
	key registry.Key,
	root registryRoot,
	keyPath string,
	depth int64,
	entries *[]registryEntry,
) error {
	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return fmt.Errorf("failed to enumerate subkeys of %s: %w", keyPath, err)
	}

	for _, subkey := range subkeys {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("registry scan canceled: %w", err)
		}

		childPath := keyPath + `\` + subkey
		if len(l.values) == 0 {
			excluded, excludeErr := l.isExcluded(childPath)
			if excludeErr != nil {
				return excludeErr
			}
			if excluded {
				continue
			}
		}
		child, err := registry.OpenKey(key, subkey, registry.READ|l.registryViewAccess())
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to open registry key %s: %w", childPath, err)
		}

		err = l.walkRegistryKey(ctx, child, root, childPath, depth+1, entries)
		closeErr := child.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return fmt.Errorf("failed to close registry key %s: %w", childPath, closeErr)
		}
	}

	return nil
}

func (l *CheckRegistry) readRegistryValues(
	key registry.Key,
	hive, keyPath string,
	written, age int64,
	entries *[]registryEntry,
) error {
	valueNames := l.values
	enumerating := len(l.values) == 1 && l.values[0] == "*"
	if enumerating {
		var err error
		valueNames, err = key.ReadValueNames(-1)
		if err != nil {
			return fmt.Errorf("failed to enumerate registry values in %s: %w", keyPath, err)
		}
	}

	for _, rawValueName := range valueNames {
		valueName := normalizeRegistryValueName(rawValueName)
		if enumerating {
			excluded, excludeErr := l.isExcluded(keyPath + `\` + registryValueDisplayName(valueName))
			if excludeErr != nil {
				return excludeErr
			}
			if excluded {
				continue
			}
		}

		entry, err := readRegistryValue(key, hive, keyPath, valueName, written, age)
		if err != nil {
			return err
		}
		if err := l.appendRegistryEntry(entries, &entry); err != nil {
			return err
		}
	}

	return nil
}

func readRegistryValue(key registry.Key, hive, keyPath, valueName string, written, age int64) (registryEntry, error) {
	displayName := registryValueDisplayName(valueName)
	entry := registryEntry{
		Kind:        "value",
		Hive:        hive,
		Path:        keyPath + `\` + displayName,
		Key:         keyPath,
		Name:        displayName,
		Exists:      true,
		Written:     written,
		Age:         age,
		ValueType:   "REG_NONE",
		StringValue: "",
	}

	data, valueType, err := getRegistryValue(key, valueName)
	if errors.Is(err, registry.ErrNotExist) {
		entry.Exists = false

		return entry, nil
	}
	if err != nil {
		return registryEntry{}, fmt.Errorf("failed to read registry value %s: %w", entry.Path, err)
	}

	entry.Size = uint64(len(data))
	entry.ValueType = registryValueTypeName(valueType)
	entry.StringValue, entry.IntegerValue = renderRegistryValue(data, valueType)

	return entry, nil
}

func getRegistryValue(key registry.Key, name string) (data []byte, valueType uint32, err error) {
	size, valueType, err := key.GetValue(name, nil)
	if err != nil {
		return nil, valueType, fmt.Errorf("failed to query registry value size: %w", err)
	}

	data = make([]byte, size)
	for {
		actual, currentType, err := key.GetValue(name, data)
		valueType = currentType
		if errors.Is(err, registry.ErrShortBuffer) {
			data = make([]byte, actual)

			continue
		}
		if err != nil {
			return nil, valueType, fmt.Errorf("failed to query registry value data: %w", err)
		}

		return data[:actual], valueType, nil
	}
}

func renderRegistryValue(data []byte, valueType uint32) (stringValue, integerValue string) {
	switch valueType {
	case registry.SZ, registry.LINK:
		return decodeRegistryUTF16(data), ""
	case registry.EXPAND_SZ:
		value := decodeRegistryUTF16(data)
		expanded, err := registry.ExpandString(value)
		if err == nil {
			value = expanded
		}

		return value, ""
	case registry.MULTI_SZ:
		return strings.Join(decodeRegistryMultiString(data), ", "), ""
	case registry.DWORD:
		if len(data) < 4 {
			return registryHexValue(data), ""
		}
		value := uint64(binary.LittleEndian.Uint32(data[:4]))

		return strconv.FormatUint(value, 10), strconv.FormatUint(value, 10)
	case registry.DWORD_BIG_ENDIAN:
		if len(data) < 4 {
			return registryHexValue(data), ""
		}
		value := uint64(binary.BigEndian.Uint32(data[:4]))

		return strconv.FormatUint(value, 10), strconv.FormatUint(value, 10)
	case registry.QWORD:
		if len(data) < registryQwordSize {
			return registryHexValue(data), ""
		}
		value := binary.LittleEndian.Uint64(data[:registryQwordSize])

		return strconv.FormatUint(value, 10), strconv.FormatUint(value, 10)
	default:
		return registryHexValue(data), ""
	}
}

func decodeRegistryUTF16(data []byte) string {
	codeUnits := make([]uint16, 0, len(data)/2)
	for index := 0; index+1 < len(data); index += 2 {
		codeUnit := binary.LittleEndian.Uint16(data[index : index+2])
		if codeUnit == 0 {
			break
		}
		codeUnits = append(codeUnits, codeUnit)
	}

	return string(utf16.Decode(codeUnits))
}

func decodeRegistryMultiString(data []byte) []string {
	values := make([]string, 0)
	current := make([]uint16, 0)
	for index := 0; index+1 < len(data); index += 2 {
		codeUnit := binary.LittleEndian.Uint16(data[index : index+2])
		if codeUnit != 0 {
			current = append(current, codeUnit)

			continue
		}
		if len(current) == 0 {
			break
		}
		values = append(values, string(utf16.Decode(current)))
		current = current[:0]
	}

	return values
}

func registryHexValue(data []byte) string {
	return "0x" + strings.ToUpper(hex.EncodeToString(data))
}

func registryValueTypeName(valueType uint32) string {
	names := map[uint32]string{
		registry.NONE:                       "REG_NONE",
		registry.SZ:                         "REG_SZ",
		registry.EXPAND_SZ:                  "REG_EXPAND_SZ",
		registry.BINARY:                     "REG_BINARY",
		registry.DWORD:                      "REG_DWORD",
		registry.DWORD_BIG_ENDIAN:           "REG_DWORD_BIG_ENDIAN",
		registry.LINK:                       "REG_LINK",
		registry.MULTI_SZ:                   "REG_MULTI_SZ",
		registry.RESOURCE_LIST:              "REG_RESOURCE_LIST",
		registry.FULL_RESOURCE_DESCRIPTOR:   "REG_FULL_RESOURCE_DESCRIPTOR",
		registry.RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
		registry.QWORD:                      "REG_QWORD",
	}
	if name, ok := names[valueType]; ok {
		return name
	}

	return fmt.Sprintf("REG_%d", valueType)
}

func parseRegistryRoot(raw string) (registryRoot, error) {
	normalized := strings.TrimSpace(raw)
	normalized = strings.Trim(normalized, `\`)
	if normalized == "" {
		return registryRoot{}, fmt.Errorf("registry key cannot be empty")
	}

	parts := strings.SplitN(normalized, `\`, 2)
	hiveName := strings.ToUpper(parts[0])
	subkey := ""
	if len(parts) == 2 {
		subkey = strings.Trim(parts[1], `\`)
	}

	root := registryRoot{subkey: subkey}
	switch hiveName {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root.hive = "HKLM"
		root.key = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		root.hive = "HKCU"
		root.key = registry.CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		root.hive = "HKCR"
		root.key = registry.CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		root.hive = "HKU"
		root.key = registry.USERS
	case "HKCC", "HKEY_CURRENT_CONFIG":
		root.hive = "HKCC"
		root.key = registry.CURRENT_CONFIG
	default:
		return registryRoot{}, fmt.Errorf("unknown registry hive %q", parts[0])
	}

	root.normalized = root.hive
	if root.subkey != "" {
		root.normalized += `\` + root.subkey
	}

	return root, nil
}

func (l *CheckRegistry) addMissingRoot(entries *[]registryEntry, root registryRoot) error {
	if len(l.values) == 0 || (len(l.values) == 1 && l.values[0] == "*") {
		return l.appendRegistryEntry(entries, &registryEntry{
			Kind:   "key",
			Hive:   root.hive,
			Path:   root.normalized,
			Key:    root.normalized,
			Name:   registryLeafName(root.normalized),
			Exists: false,
		})
	}

	for _, rawValueName := range l.values {
		valueName := normalizeRegistryValueName(rawValueName)
		displayName := registryValueDisplayName(valueName)
		if err := l.appendRegistryEntry(entries, &registryEntry{
			Kind:      "value",
			Hive:      root.hive,
			Path:      root.normalized + `\` + displayName,
			Key:       root.normalized,
			Name:      displayName,
			Exists:    false,
			ValueType: "REG_NONE",
		}); err != nil {
			return err
		}
	}

	return nil
}

func (l *CheckRegistry) appendRegistryEntry(entries *[]registryEntry, entry *registryEntry) error {
	if int64(len(*entries)) >= l.maxEntries {
		return fmt.Errorf("maximum number of registry entries reached, increase max-entries to allow more")
	}

	*entries = append(*entries, *entry)

	return nil
}

func (l *CheckRegistry) registryViewAccess() uint32 {
	switch l.view {
	case "32":
		return registry.WOW64_32KEY
	case "64":
		return registry.WOW64_64KEY
	default:
		return 0
	}
}

func (l *CheckRegistry) isExcluded(path string) (bool, error) {
	for _, pattern := range l.excludes {
		matched, err := doublestar.PathMatch(
			strings.ToLower(strings.TrimSpace(pattern)),
			strings.ToLower(path),
		)
		if err != nil {
			return false, fmt.Errorf("invalid exclude path pattern %q: %w", pattern, err)
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}

func registryKeyTimes(info *registry.KeyInfo) (written, age int64) {
	modified := info.ModTime()
	written = modified.Unix()
	age = max(int64(time.Since(modified).Seconds()), 0)

	return written, age
}

func registryLeafName(path string) string {
	if index := strings.LastIndex(path, `\`); index >= 0 {
		return path[index+1:]
	}

	return path
}

func normalizeRegistryValueName(name string) string {
	if strings.EqualFold(strings.TrimSpace(name), "(default)") {
		return ""
	}

	return name
}

func registryValueDisplayName(name string) string {
	if name == "" {
		return "(default)"
	}

	return name
}
