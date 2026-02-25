package e2ewebsocket

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenKeys(t *testing.T) {
	cwd, _ := os.Getwd()
	keyStorePath := filepath.Join(filepath.Dir(cwd), "static_key")
	os.RemoveAll(keyStorePath)
	os.MkdirAll(keyStorePath, 0755)

	setupKeyStore(t, keyStorePath, "1111111111")
	setupKeyStore(t, keyStorePath, "2222222222")
	setupKeyStore(t, keyStorePath, "3333333333")

	exchangeKeys(t, keyStorePath, "1111111111", "2222222222")
	exchangeKeys(t, keyStorePath, "1111111111", "3333333333")
	exchangeKeys(t, keyStorePath, "2222222222", "3333333333")
}
