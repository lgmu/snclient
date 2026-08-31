//go:build windows

package snclient

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

func TestCheckRegistryWindows(t *testing.T) {
	rootPath := prepareRegistryTestData(t)
	t.Run("configured entry limit", func(t *testing.T) {
		limitedSnc := StartTestAgent(t, `
[/settings/check/registry]
max entries limit = 2
`)
		t.Cleanup(func() { StopTestAgent(t, limitedSnc) })

		res := limitedSnc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "value=*", "max-entries=100"})
		assert.Equal(t, CheckExitUnknown, res.State)
		assert.Contains(t, string(res.BuildPluginOutput()), "maximum number of registry entries reached")
	})

	snc := StartTestAgent(t, "")
	t.Cleanup(func() { StopTestAgent(t, snc) })

	t.Run("existing key", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath})
		require.Equal(t, CheckExitOK, res.State)
		require.Len(t, res.Raw.listData, 1)
		assert.Equal(t, "key", res.Raw.listData[0]["kind"])
		assert.Equal(t, "true", res.Raw.listData[0]["exists"])
		assert.Equal(t, "1", res.Raw.listData[0]["subkey_count"])
	})

	t.Run("missing key", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath + `\\Missing`})
		assert.Equal(t, CheckExitCritical, res.State)
		assert.Contains(t, string(res.BuildPluginOutput()), "exists=false")
	})

	t.Run("specific string value", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "value=Version"})
		require.Equal(t, CheckExitOK, res.State)
		require.Len(t, res.Raw.listData, 1)
		assert.Equal(t, "REG_SZ", res.Raw.listData[0]["type"])
		assert.Equal(t, "1.2.3", res.Raw.listData[0]["value_str"])
	})

	t.Run("unnamed value", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "value=(default)"})
		require.Equal(t, CheckExitOK, res.State)
		require.Len(t, res.Raw.listData, 1)
		assert.Equal(t, "(default)", res.Raw.listData[0]["name"])
		assert.Equal(t, "default value", res.Raw.listData[0]["value_str"])
	})

	t.Run("missing value", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "value=Missing"})
		assert.Equal(t, CheckExitCritical, res.State)
		require.Len(t, res.Raw.listData, 1)
		assert.Equal(t, "false", res.Raw.listData[0]["exists"])
		assert.Equal(t, "REG_NONE", res.Raw.listData[0]["type"])
	})

	t.Run("enumerate and exclude values", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "value=*", "exclude=HKCU\\**\\Cac*"})
		require.Equal(t, CheckExitOK, res.State)
		for _, entry := range res.Raw.listData {
			assert.NotEqual(t, "Cache", entry["name"])
		}
		assert.GreaterOrEqual(t, len(res.Raw.listData), 6)
	})

	t.Run("recursive key depth and exclusion", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "recursive", "max-depth=1"})
		require.Equal(t, CheckExitOK, res.State)
		assert.Len(t, res.Raw.listData, 2)

		res = snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "recursive", "exclude=HKCU\\**\\Ch*"})
		require.Equal(t, CheckExitOK, res.State)
		assert.Len(t, res.Raw.listData, 1)
	})

	t.Run("recursive values", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "value=*", "recursive", "max-depth=1"})
		require.Equal(t, CheckExitOK, res.State)
		assert.Contains(t, registryEntryNames(res.Raw.listData), "ChildValue")
		assert.NotContains(t, registryEntryNames(res.Raw.listData), "GrandchildValue")
	})

	t.Run("numeric threshold and performance data", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{
			"key=HKCU\\" + rootPath,
			"value=Number",
			"warn=value_int > 40",
			"crit=value_int > 50",
		})
		require.Equal(t, CheckExitWarning, res.State)
		assert.Contains(t, string(res.BuildPluginOutput()), "value_int'=42")
	})

	t.Run("entry limit", func(t *testing.T) {
		res := snc.RunCheck("check_registry", []string{"key=HKCU\\" + rootPath, "value=*", "max-entries=1"})
		assert.Equal(t, CheckExitUnknown, res.State)
		assert.Contains(t, string(res.BuildPluginOutput()), "maximum number of registry entries reached")
	})
}

func TestRenderRegistryValue(t *testing.T) {
	dword := make([]byte, 4)
	binary.LittleEndian.PutUint32(dword, 42)
	stringValue, integerValue := renderRegistryValue(dword, registry.DWORD)
	assert.Equal(t, "42", stringValue)
	assert.Equal(t, "42", integerValue)

	qword := make([]byte, 8)
	binary.LittleEndian.PutUint64(qword, 123456789)
	stringValue, integerValue = renderRegistryValue(qword, registry.QWORD)
	assert.Equal(t, "123456789", stringValue)
	assert.Equal(t, "123456789", integerValue)

	stringValue, integerValue = renderRegistryValue([]byte{0xde, 0xad, 0xbe, 0xef}, registry.BINARY)
	assert.Equal(t, "0xDEADBEEF", stringValue)
	assert.Empty(t, integerValue)
}

func TestParseRegistryRoot(t *testing.T) {
	root, err := parseRegistryRoot(`HKEY_LOCAL_MACHINE\Software\SNClient\`)
	require.NoError(t, err)
	assert.Equal(t, "HKLM", root.hive)
	assert.Equal(t, `Software\SNClient`, root.subkey)
	assert.Equal(t, `HKLM\Software\SNClient`, root.normalized)

	_, err = parseRegistryRoot(`UNKNOWN\Software`)
	assert.ErrorContains(t, err, "unknown registry hive")
}

func prepareRegistryTestData(t *testing.T) string {
	t.Helper()

	rootPath := fmt.Sprintf(`Software\SNClientTests\check_registry_%d`, time.Now().UnixNano())
	root, _, err := registry.CreateKey(registry.CURRENT_USER, rootPath, registry.ALL_ACCESS)
	require.NoError(t, err)

	require.NoError(t, root.SetStringValue("Version", "1.2.3"))
	require.NoError(t, root.SetDWordValue("Number", 42))
	require.NoError(t, root.SetQWordValue("LargeNumber", 123456789))
	require.NoError(t, root.SetBinaryValue("Binary", []byte{0xde, 0xad, 0xbe, 0xef}))
	require.NoError(t, root.SetStringsValue("Names", []string{"one", "two"}))
	require.NoError(t, root.SetStringValue("Cache", "ignore me"))
	require.NoError(t, root.SetStringValue("", "default value"))
	require.NoError(t, root.Close())

	child, _, err := registry.CreateKey(registry.CURRENT_USER, rootPath+`\Child`, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, child.SetStringValue("ChildValue", "child"))
	require.NoError(t, child.Close())

	grandchild, _, err := registry.CreateKey(registry.CURRENT_USER, rootPath+`\Child\Grandchild`, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, grandchild.SetStringValue("GrandchildValue", "grandchild"))
	require.NoError(t, grandchild.Close())

	t.Cleanup(func() {
		deleteRegistryTestTree(t, registry.CURRENT_USER, rootPath)
	})

	return rootPath
}

func deleteRegistryTestTree(t *testing.T, parent registry.Key, path string) {
	t.Helper()

	key, err := registry.OpenKey(parent, path, registry.ALL_ACCESS)
	if err != nil {
		return
	}
	subkeys, err := key.ReadSubKeyNames(-1)
	require.NoError(t, err)
	for _, subkey := range subkeys {
		deleteRegistryTestTree(t, key, subkey)
	}
	require.NoError(t, key.Close())
	require.NoError(t, registry.DeleteKey(parent, path))
}

func registryEntryNames(entries []map[string]string) string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry["name"])
	}

	return strings.Join(names, ",")
}
