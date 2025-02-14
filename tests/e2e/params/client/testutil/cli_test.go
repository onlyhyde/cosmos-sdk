//go:build e2e
// +build e2e

package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cosmos/cosmos-sdk/testutil/network"
	clienttestutil "github.com/cosmos/cosmos-sdk/x/params/client/testutil"
	"github.com/cosmos/cosmos-sdk/x/params/testutil"
)

func TestIntegrationTestSuite(t *testing.T) {
	cfg, err := network.DefaultConfigWithAppConfig(testutil.AppConfig)
	require.NoError(t, err)
	cfg.NumValidators = 1
	suite.Run(t, clienttestutil.NewIntegrationTestSuite(cfg))
}
