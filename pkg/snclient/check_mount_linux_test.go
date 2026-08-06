package snclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMount(t *testing.T) {
	snc := StartTestAgent(t, "")

	res := snc.RunCheck("check_mount", []string{"mount=/not_there", "options=rw,relatime"})
	assert.Equalf(t, CheckExitCritical, res.State, "state Critical")
	assert.Contains(t, string(res.BuildPluginOutput()), "CRITICAL - mount /not_there not mounted", "output matches")

	res = snc.RunCheck("check_mount", []string{"mount=/"})
	assert.Equalf(t, CheckExitOK, res.State, "state OK")
	assert.Contains(t, string(res.BuildPluginOutput()), "OK - 1 mount(s) as expected", "output matches")

	res = snc.RunCheck("check_mount", []string{"mount=/tmpppp", "mount=/"})
	assert.Equalf(t, CheckExitCritical, res.State, "state Critical")
	assert.Contains(t, string(res.BuildPluginOutput()), "CRITICAL - critical(mount /tmpppp not mounted)", "output matches")

	res = snc.RunCheck("check_mount", []string{"mount=/", "critical=mount eq '/' and options ne 'dummyoptions'"})
	assert.Equalf(t, CheckExitCritical, res.State, "state Critical")
	assert.Contains(t, string(res.BuildPluginOutput()), "CRITICAL - critical(mount / )", "output matches")

	inv, err := snc.getInventoryEntry(t.Context(), "check_mount")
	require.NoError(t, err)
	require.NotEmptyf(t, inv, "expected mounts list to be non-empty")
	res = snc.RunCheck("check_mount", []string{"mount=" + inv[0]["mount"], "options=" + inv[0]["options"], "fstype=" + inv[0]["fstype"]})
	assert.Equalf(t, CheckExitOK, res.State, "state OK")
	assert.Contains(t, string(res.BuildPluginOutput()), "OK - 1 mount(s) as expected", "output matches")

	StopTestAgent(t, snc)
}
