---
title: registry
---

## check_registry

Checks Windows registry keys and values.

- [Examples](#examples)
- [Argument Defaults](#argument-defaults)
- [Attributes](#attributes)

## Implementation

| Windows            | Linux | FreeBSD | MacOSX |
|:------------------:|:-----:|:-------:|:------:|
| :white_check_mark: |       |         |        |

## Examples

### Default Check

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

### Example using NRPE and Naemon

Naemon Config

    define command{
        command_name         check_nrpe
        command_line         $USER1$/check_nrpe -H $HOSTADDRESS$ -n -c $ARG1$ -a $ARG2$
    }

    define service {
        host_name            testhost
        service_description  check_registry
        use                  generic-service
        check_command        check_nrpe!check_registry!"key=HKLM\Software\MyApp" "value=InstallVersion" "crit+=type != 'REG_SZ'"
    }

## Argument Defaults

| Argument      | Default Value                                                                                         |
| ------------- | ----------------------------------------------------------------------------------------------------- |
| filter        | none                                                                                                  |
| critical      | exists = false                                                                                        |
| empty-state   | 3 (UNKNOWN)                                                                                           |
| empty-syntax  | %(status) - No registry items found                                                                   |
| top-syntax    | %(status) - %(problem_list)                                                                           |
| ok-syntax     | %(status) - {{ IF count == 1 }}%(list){{ ELSE }}All %(count) registry item(s) are ok.{{ END }}        |
| detail-syntax | \${path}{{ IF kind == 'key' }}: exists=\${exists}, subkeys=\${subkey_count}, values=\${value_count}{{ ELSE }}: \${value_str} (type=\${type}){{ END }} |

## Check Specific Arguments

| Argument    | Description                                                                                             |
| ----------- | ------------------------------------------------------------------------------------------------------- |
| exclude     | Case-insensitive path glob for omitting discovered registry entries. Use \* within one path segment or \*\* across subkeys. |
| key         | Registry key to check. Can be specified multiple times (for example: HKLM\Software\MyApp).              |
| max-depth   | Maximum recursion depth below the starting key. -1 is unlimited. Requires recursive. Default: -1        |
| max-entries | Maximum number of registry entries to process. Default: 5000                                            |
| recursive   | Recursively enumerate subkeys. In value mode, values in the subkeys are included as well. Default: false |
| timezone    | Sets the timezone for time metrics (default is local time)                                              |
| value       | Registry value to check. Can be specified multiple times. Use '\*' to enumerate all values or '(default)' for the unnamed value. If omitted, registry keys are checked. |
| view        | Registry view: default, 32, or 64. Default: default                                                     |

## Attributes

### Filter Keywords

these can be used in filters and thresholds (along with the default attributes):

| Attribute    | Description                                                                                  |
| ------------ | -------------------------------------------------------------------------------------------- |
| kind         | Registry entry kind: key or value                                                            |
| hive         | Registry hive abbreviation (HKLM, HKCU, HKCR, HKU, or HKCC)                                  |
| path         | Full registry entry path, including the value name for value entries                         |
| key          | Full registry key path. For value entries, this is the containing key                        |
| name         | Leaf key or value name. The unnamed registry value is shown as (default)                     |
| exists       | Whether the registry key or value exists                                                     |
| written      | Unix timestamp when the key was last written. Value entries use the containing key timestamp |
| age          | Seconds since the key was last written                                                       |
| subkey_count | Number of immediate subkeys (key entries only)                                               |
| value_count  | Number of values in the key (key entries only)                                               |
| type         | Registry value type, such as REG_SZ, REG_DWORD, or REG_BINARY (value entries only)           |
| value_str    | Registry value rendered as text (value entries only)                                         |
| value_int    | Numeric value for REG_DWORD, REG_DWORD_BIG_ENDIAN, and REG_QWORD values                      |
| size         | Raw registry value data size in bytes (value entries only)                                   |
