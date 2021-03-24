package ledger

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/legacy"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func TestErrorHandling(t *testing.T) {
	// first, try to generate a key, must return an error
	// (no panic)
	path := *hd.NewParams(44, 555, 0, false, 0)
	_, err := NewPrivKeySecp256k1Unsafe(path)
	require.Error(t, err)
}

func TestPublicKeyUnsafe(t *testing.T) {
	path := *hd.NewFundraiserParams(0, sdk.CoinType, 0)
	priv, err := NewPrivKeySecp256k1Unsafe(path)
	require.NoError(t, err)
	checkDefaultPubKey(t, priv)
}

func checkDefaultPubKey(t *testing.T, priv types.LedgerPrivKey) {
	require.NotNil(t, priv)
	expectedPkStr := "PubKeySecp256k1{034FEF9CD7C4C63588D3B03FEB5281B9D232CBA34D6F3D71AEE59211FFBFE1FE87}"
	require.Equal(t, "eb5ae98721034fef9cd7c4c63588d3b03feb5281b9d232cba34d6f3d71aee59211ffbfe1fe87",
		fmt.Sprintf("%x", cdc.Amino.MustMarshalBinaryBare(priv.PubKey())),
		"Is your device using test mnemonic: %s ?", testutil.TestMnemonic)
	require.Equal(t, expectedPkStr, priv.PubKey().String())
	addr := sdk.AccAddress(priv.PubKey().Address()).String()
	require.Equal(t, "cosmos1w34k53py5v5xyluazqpq65agyajavep2rflq6h",
		addr, "Is your device using test mnemonic: %s ?", testutil.TestMnemonic)
}

func TestPublicKeyUnsafeHDPath(t *testing.T) {
	expectedAnswers := []string{
		`{"key":"A0/vnNfExjWI07A/61KBudIyy6NNbz1xruWSEf+/4f6H"}`,
		`{"key":"AmDQSHo9/Okiju4tDYOkD2Ex9VFSbI5SBm/n/h5KUJZm"}`,
		`{"key":"A6JnA5PQKxYtDtBqCAQegNhr42wFZDNSVN90YkR+tpqz"}`,
		`{"key":"AzIi/GF5UHd5FmVUSpB0Do6tY4o5GjuPkmH0oiazlsBC"}`,
		`{"key":"A/V3RzNI17AeevLyReNrmNGBvJNeyLVSzeWTK2Rtx74E"}`,
		`{"key":"AiKxpUhr4KLV88WGa+RuBdG96M2l6hxMd6m8SNL6J1O8"}`,
		`{"key":"A3ehyCbToDyk7pT8TeprzLK6xfKsBBmhKMKfjojx/yla"}`,
		`{"key":"Axt1yERTk1q3b4yNC2Vmw/zBAcxcWdcAC/yRAZYekwjZ"}`,
		`{"key":"A4kFpCQzsdZ3zIr9NoYUMLmoUpFxsGFvczZZ8THD+AIh"}`,
		`{"key":"A4vn80iQLYwgvIjTIpT087gZKEVIEiIp3s0a3xp+sISL"}`,
	}

	const numIters = 10

	privKeys := make([]types.LedgerPrivKey, numIters)

	// Check with device
	for i := uint32(0); i < 10; i++ {
		path := *hd.NewFundraiserParams(0, sdk.CoinType, i)
		t.Logf("Checking keys at %v\n", path)

		priv, err := NewPrivKeySecp256k1Unsafe(path)
		require.NoError(t, err)
		require.NotNil(t, priv)

		// Check other methods
		tmp := priv.(PrivKeyLedgerSecp256k1)
		require.NoError(t, tmp.ValidateKey())
		(&tmp).AssertIsPrivKeyInner()

		// in this test we are chekcking if the generated keys are correct, so no need to wrap into Any.
		pkBz, err := codec.ProtoMarshalJSON(priv.PubKey(), nil)
		require.NoError(t, err)
		require.Equal(t,
			expectedAnswers[i], string(pkBz),
			"Is your device using test mnemonic: %s ?", testutil.TestMnemonic)

		// Store and restore
		serializedPk := priv.Bytes()
		require.NotNil(t, serializedPk)
		require.True(t, len(serializedPk) >= 50)

		privKeys[i] = priv
	}

	// Now check equality
	for i := 0; i < 10; i++ {
		for j := 0; j < 10; j++ {
			require.Equal(t, i == j, privKeys[i].Equals(privKeys[j]))
			require.Equal(t, i == j, privKeys[j].Equals(privKeys[i]))
		}
	}
}

func TestPublicKeySafe(t *testing.T) {
	path := *hd.NewFundraiserParams(0, sdk.CoinType, 0)
	priv, addr, err := NewPrivKeySecp256k1(path, "cosmos")

	require.NoError(t, err)
	require.NotNil(t, priv)
	require.Nil(t, ShowAddress(path, priv.PubKey(), sdk.GetConfig().GetBech32AccountAddrPrefix()))
	checkDefaultPubKey(t, priv)

	addr2 := sdk.AccAddress(priv.PubKey().Address()).String()
	require.Equal(t, addr, addr2)
}

func TestPublicKeyHDPath(t *testing.T) {
	expectedPubKeys := []string{
		`{"key":"A0/vnNfExjWI07A/61KBudIyy6NNbz1xruWSEf+/4f6H"}`,
		`{"key":"AmDQSHo9/Okiju4tDYOkD2Ex9VFSbI5SBm/n/h5KUJZm"}`,
		`{"key":"A6JnA5PQKxYtDtBqCAQegNhr42wFZDNSVN90YkR+tpqz"}`,
		`{"key":"AzIi/GF5UHd5FmVUSpB0Do6tY4o5GjuPkmH0oiazlsBC"}`,
		`{"key":"A/V3RzNI17AeevLyReNrmNGBvJNeyLVSzeWTK2Rtx74E"}`,
		`{"key":"AiKxpUhr4KLV88WGa+RuBdG96M2l6hxMd6m8SNL6J1O8"}`,
		`{"key":"A3ehyCbToDyk7pT8TeprzLK6xfKsBBmhKMKfjojx/yla"}`,
		`{"key":"Axt1yERTk1q3b4yNC2Vmw/zBAcxcWdcAC/yRAZYekwjZ"}`,
		`{"key":"A4kFpCQzsdZ3zIr9NoYUMLmoUpFxsGFvczZZ8THD+AIh"}`,
		`{"key":"A4vn80iQLYwgvIjTIpT087gZKEVIEiIp3s0a3xp+sISL"}`,
	}

	expectedAddrs := []string{
		"cosmos1w34k53py5v5xyluazqpq65agyajavep2rflq6h",
		"cosmos19ewxwemt6uahejvwf44u7dh6tq859tkyvarh2q",
		"cosmos1a07dzdjgjsntxpp75zg7cgatgq0udh3pcdcxm3",
		"cosmos1qvw52lmn9gpvem8welghrkc52m3zczyhlqjsl7",
		"cosmos17m78ka80fqkkw2c4ww0v4xm5nsu2drgrlm8mn2",
		"cosmos1ferh9ll9c452d2p8k2v7heq084guygkn43up9e",
		"cosmos10vf3sxmjg96rqq36axcphzfsl74dsntuehjlw5",
		"cosmos1cq83av8cmnar79h0rg7duh9gnr7wkh228a7fxg",
		"cosmos1dszhfrt226jy5rsre7e48vw9tgwe90uerfyefa",
		"cosmos1734d7qsylzrdt05muhqqtpd90j8mp4y6rzch8l",
	}

	const numIters = 10

	privKeys := make([]types.LedgerPrivKey, numIters)

	// Check with device
	for i := 0; i < len(expectedAddrs); i++ {
		path := *hd.NewFundraiserParams(0, sdk.CoinType, uint32(i))
		t.Logf("Checking keys at %s\n", path)

		priv, addr, err := NewPrivKeySecp256k1(path, "cosmos")
		require.NoError(t, err)
		require.NotNil(t, addr)
		require.NotNil(t, priv)

		addr2 := sdk.AccAddress(priv.PubKey().Address()).String()
		require.Equal(t, addr2, addr)
		require.Equal(t,
			expectedAddrs[i], addr,
			"Is your device using test mnemonic: %s ?", testutil.TestMnemonic)

		// Check other methods
		tmp := priv.(PrivKeyLedgerSecp256k1)
		require.NoError(t, tmp.ValidateKey())
		(&tmp).AssertIsPrivKeyInner()

		// in this test we are chekcking if the generated keys are correct and stored in a right path, so no need to wrap into Any.
		pkBz, err := codec.ProtoMarshalJSON(priv.PubKey(), nil)
		require.NoError(t, err)
		require.Equal(t,
			expectedPubKeys[i], string(pkBz),
			"Is your device using test mnemonic: %s ?", testutil.TestMnemonic)

		// Store and restore
		serializedPk := priv.Bytes()
		require.NotNil(t, serializedPk)
		require.True(t, len(serializedPk) >= 50)

		privKeys[i] = priv
	}

	// Now check equality
	for i := 0; i < 10; i++ {
		for j := 0; j < 10; j++ {
			require.Equal(t, i == j, privKeys[i].Equals(privKeys[j]))
			require.Equal(t, i == j, privKeys[j].Equals(privKeys[i]))
		}
	}
}

func getFakeTx(accountNumber uint32) []byte {
	tmp := fmt.Sprintf(
		`{"account_number":"%d","chain_id":"1234","fee":{"amount":[{"amount":"150","denom":"atom"}],"gas":"5000"},"memo":"memo","msgs":[[""]],"sequence":"6"}`,
		accountNumber)

	return []byte(tmp)
}

func TestSignaturesHD(t *testing.T) {
	for account := uint32(0); account < 100; account += 30 {
		msg := getFakeTx(account)

		path := *hd.NewFundraiserParams(account, sdk.CoinType, account/5)
		t.Logf("Checking signature at %v    ---   PLEASE REVIEW AND ACCEPT IN THE DEVICE\n", path)

		priv, err := NewPrivKeySecp256k1Unsafe(path)
		require.NoError(t, err)

		pub := priv.PubKey()
		sig, err := priv.Sign(msg)
		require.NoError(t, err)

		valid := pub.VerifySignature(msg, sig)
		require.True(t, valid, "Is your device using test mnemonic: %s ?", testutil.TestMnemonic)
	}
}

func TestRealDeviceSecp256k1(t *testing.T) {
	msg := getFakeTx(50)
	path := *hd.NewFundraiserParams(0, sdk.CoinType, 0)
	priv, err := NewPrivKeySecp256k1Unsafe(path)
	require.NoError(t, err)

	pub := priv.PubKey()
	sig, err := priv.Sign(msg)
	require.NoError(t, err)

	valid := pub.VerifySignature(msg, sig)
	require.True(t, valid)

	// now, let's serialize the public key and make sure it still works
	bs := cdc.Amino.MustMarshalBinaryBare(priv.PubKey())
	pub2, err := legacy.PubKeyFromBytes(bs)
	require.Nil(t, err, "%+v", err)

	// make sure we get the same pubkey when we load from disk
	require.Equal(t, pub, pub2)

	// signing with the loaded key should match the original pubkey
	sig, err = priv.Sign(msg)
	require.NoError(t, err)
	valid = pub.VerifySignature(msg, sig)
	require.True(t, valid)

	// make sure pubkeys serialize properly as well
	bs = legacy.Cdc.MustMarshalBinaryBare(pub)
	bpub, err := legacy.PubKeyFromBytes(bs)
	require.NoError(t, err)
	require.Equal(t, pub, bpub)
}
