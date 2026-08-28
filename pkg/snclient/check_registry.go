package snclient

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/consol-monitoring/snclient/pkg/convert"
)

const (
	CheckRegistryDefaultMaxDepth   = int64(-1)
	CheckRegistryDefaultMaxEntries = int64(5000)
	CheckRegistryMaxEntriesLimit   = int64(20000)
)

type CheckRegistry struct {
	keys       []string
	values     []string
	excludes   CommaStringList
	view       string
	recursive  bool
	maxDepth   int64
	maxEntries int64
}

type registryEntry struct {
	Kind         string
	Hive         string
	Path         string
	Key          string
	Name         string
	Exists       bool
	Written      int64
	Age          int64
	SubkeyCount  uint32
	ValueCount   uint32
	ValueType    string
	StringValue  string
	IntegerValue string
	Size         uint64
}

func init() {
	AvailableChecks["check_registry"] = CheckEntry{"check_registry", NewCheckRegistry}
}

func NewCheckRegistry() CheckHandler {
	return &CheckRegistry{
		view:       "default",
		maxDepth:   CheckRegistryDefaultMaxDepth,
		maxEntries: CheckRegistryDefaultMaxEntries,
	}
}

//nolint:funlen // check metadata is kept together so generated help stays easy to review
func (l *CheckRegistry) Build() *CheckData {
	return &CheckData{
		name:        "check_registry",
		description: "Checks Windows registry keys and values.",
		implemented: Windows,
		result: &CheckResult{
			State: CheckExitOK,
		},
		args: map[string]CheckArgument{
			"key": {
				value:       &l.keys,
				description: `Registry key to check. Can be specified multiple times (for example: HKLM\Software\MyApp).`,
			},
			"value": {
				value:       &l.values,
				description: "Registry value to check. Can be specified multiple times. Use '*' to enumerate all values or '(default)' for the unnamed value. If omitted, registry keys are checked.",
			},
			"exclude": {
				value:       &l.excludes,
				description: "Case-insensitive path glob for omitting discovered registry entries. Use * within one path segment or ** across subkeys.",
			},
			"view": {
				value:       &l.view,
				description: "Registry view: default, 32, or 64. Default: default",
			},
			"recursive": {
				value:       &l.recursive,
				description: "Recursively enumerate subkeys. In value mode, values in the subkeys are included as well. Default: false",
			},
			"max-depth": {
				value:       &l.maxDepth,
				description: "Maximum recursion depth below the starting key. -1 is unlimited. Requires recursive. Default: -1",
			},
			"max-entries": {
				value:       &l.maxEntries,
				description: fmt.Sprintf("Maximum number of registry entries to process. Default: %d", CheckRegistryDefaultMaxEntries),
			},
			"timezone": {description: "Sets the timezone for time metrics (default is local time)"},
		},
		defaultFilter:   "none",
		defaultCritical: "exists = false",
		detailSyntax: `${path}{{ IF kind == 'key' }}: exists=${exists}, subkeys=${subkey_count}, values=${value_count}` +
			`{{ ELSE }}: ${value_str} (type=${type}){{ END }}`,
		topSyntax:   "%(status) - %(problem_list)",
		okSyntax:    "%(status) - {{ IF count == 1 }}%(list){{ ELSE }}All %(count) registry item(s) are ok.{{ END }}",
		emptySyntax: "%(status) - No registry items found",
		emptyState:  CheckExitUnknown,
		listSorted:  []string{"path", "kind"},
		attributes: []CheckAttribute{
			{name: "kind", description: "Registry entry kind: key or value"},
			{name: "hive", description: "Registry hive abbreviation (HKLM, HKCU, HKCR, HKU, or HKCC)"},
			{name: "path", description: "Full registry entry path, including the value name for value entries"},
			{name: "key", description: "Full registry key path. For value entries, this is the containing key"},
			{name: "name", description: "Leaf key or value name. The unnamed registry value is shown as (default)"},
			{name: "exists", description: "Whether the registry key or value exists", unit: UBool},
			{name: "written", description: "Unix timestamp when the key was last written. Value entries use the containing key timestamp", unit: UDate},
			{name: "age", description: "Seconds since the key was last written", unit: UDuration},
			{name: "subkey_count", description: "Number of immediate subkeys (key entries only)"},
			{name: "value_count", description: "Number of values in the key (key entries only)"},
			{name: "type", description: "Registry value type, such as REG_SZ, REG_DWORD, or REG_BINARY (value entries only)"},
			{name: "value_str", description: "Registry value rendered as text (value entries only)"},
			{name: "value_int", description: "Numeric value for REG_DWORD, REG_DWORD_BIG_ENDIAN, and REG_QWORD values"},
			{name: "size", description: "Raw registry value data size in bytes (value entries only)", unit: UByte},
		},
		exampleDefault: `
Check whether a registry key exists:

    check_registry "key=HKLM\Software\Microsoft\Windows NT\CurrentVersion"
    OK - HKLM\Software\Microsoft\Windows NT\CurrentVersion: exists=true, subkeys=8, values=27

Read a specific registry value:

    check_registry "key=HKLM\Software\Microsoft\Windows NT\CurrentVersion" "value=ProductName"
    OK - HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProductName: Windows 11 Pro (type=REG_SZ)

Enumerate values recursively:

    check_registry "key=HKLM\Software\MyApp" "value=*" "recursive" "max-depth=2" "exclude=HKLM\Software\MyApp\**\Cache*"

Check a numeric registry value. crit+ keeps the default 'exists = false' condition:

    check_registry "key=HKLM\System\CurrentControlSet\Services\W32Time\Config" "value=MaxPollInterval" "warn=value_int > 14" "crit+=value_int > 17"
	`,
		exampleArgs: `"key=HKLM\Software\MyApp" "value=InstallVersion" "crit+=type != 'REG_SZ'"`,
	}
}

func (l *CheckRegistry) Check(ctx context.Context, snc *Agent, check *CheckData, _ []Argument) (*CheckResult, error) {
	if err := l.validate(check); err != nil {
		return nil, err
	}
	if err := l.applyMaxEntriesLimit(snc); err != nil {
		return nil, err
	}

	entries, err := l.queryRegistry(ctx)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(entries))
	for index := range entries {
		entry := &entries[index]
		entryKey := strings.ToLower(entry.Kind + "\x00" + entry.Path)
		if seen[entryKey] {
			continue
		}
		seen[entryKey] = true

		data := entry.data()
		check.listData = append(check.listData, data)
		l.addMetrics(check, entry, data)
	}

	check.addCountMetrics = check.HasThreshold("count")
	check.addProblemCountMetrics = check.HasThreshold("problem_count")

	return check.Finalize()
}

func (l *CheckRegistry) validate(check *CheckData) error {
	if len(l.keys) == 0 {
		return fmt.Errorf("no registry key specified")
	}

	l.view = strings.ToLower(strings.TrimSpace(l.view))
	if !slices.Contains([]string{"default", "32", "64"}, l.view) {
		return fmt.Errorf("invalid registry view %q: expected default, 32, or 64", l.view)
	}
	if l.maxDepth < -1 {
		return fmt.Errorf("max-depth must be -1 or greater")
	}
	if check.hasArgsSupplied["max-depth"] && !l.recursive {
		return fmt.Errorf("max-depth requires recursive")
	}
	if l.maxEntries <= 0 {
		return fmt.Errorf("max-entries must be greater than 0")
	}
	if slices.Contains(l.values, "*") && len(l.values) > 1 {
		return fmt.Errorf("value=* cannot be combined with specific registry values")
	}

	return nil
}

func (l *CheckRegistry) applyMaxEntriesLimit(snc *Agent) error {
	maxEntriesLimit, ok, err := snc.config.Section("/settings/check/registry").GetInt("max entries limit")
	if err != nil || !ok {
		maxEntriesLimit = CheckRegistryMaxEntriesLimit
	}
	l.maxEntries = min(l.maxEntries, maxEntriesLimit)
	if l.maxEntries <= 0 {
		return fmt.Errorf("max-entries must be greater than 0")
	}

	return nil
}

func (entry *registryEntry) data() map[string]string {
	return map[string]string{
		"kind":         entry.Kind,
		"hive":         entry.Hive,
		"path":         entry.Path,
		"key":          entry.Key,
		"name":         entry.Name,
		"exists":       fmt.Sprintf("%t", entry.Exists),
		"written":      fmt.Sprintf("%d", entry.Written),
		"age":          fmt.Sprintf("%d", entry.Age),
		"subkey_count": fmt.Sprintf("%d", entry.SubkeyCount),
		"value_count":  fmt.Sprintf("%d", entry.ValueCount),
		"type":         entry.ValueType,
		"value_str":    entry.StringValue,
		"value_int":    entry.IntegerValue,
		"size":         fmt.Sprintf("%d", entry.Size),
	}
}

func (l *CheckRegistry) addMetrics(check *CheckData, entry *registryEntry, data map[string]string) {
	if !entry.Exists {
		return
	}

	metrics := []struct {
		attribute string
		value     string
		unit      string
	}{
		{attribute: "written", value: data["written"]},
		{attribute: "age", value: data["age"], unit: "s"},
		{attribute: "subkey_count", value: data["subkey_count"]},
		{attribute: "value_count", value: data["value_count"]},
		{attribute: "value_int", value: data["value_int"]},
		{attribute: "size", value: data["size"], unit: "B"},
	}

	for _, metric := range metrics {
		if metric.value == "" || !check.HasThreshold(metric.attribute) {
			continue
		}

		check.result.Metrics = append(check.result.Metrics, &CheckMetric{
			Name:          entry.Path + " " + metric.attribute,
			ThresholdName: metric.attribute,
			Value:         convert.UInt64(metric.value),
			Unit:          metric.unit,
			Warning:       check.warnThreshold,
			Critical:      check.critThreshold,
			Min:           &Zero,
			Entry:         data,
		})
	}
}
