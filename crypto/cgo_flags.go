package crypto

/*
#cgo CFLAGS: -I${SRCDIR}/../third_party/tongsuo-install/include -DOPENSSL_API_COMPAT=0x10100000L
#cgo LDFLAGS: -L${SRCDIR}/../third_party/tongsuo-install -L${SRCDIR}/../third_party/tongsuo-install/lib -lcrypto -lssl
#cgo !windows LDFLAGS: -Wl,-rpath,${SRCDIR}/../third_party/tongsuo-install/lib
*/
import "C"
