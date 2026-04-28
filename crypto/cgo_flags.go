package crypto

/*
#cgo CFLAGS: -I${SRCDIR}/../third_party/tongsuo-install/include -DOPENSSL_API_COMPAT=0x10100000L

// Default (Windows/Linux host)
#cgo !android LDFLAGS: -L${SRCDIR}/../third_party/tongsuo-install -L${SRCDIR}/../third_party/tongsuo-install/lib -L${SRCDIR}/sm2keyexch -lcrypto -lssl -lkeyexchange
#cgo linux,!android LDFLAGS: -Wl,-rpath,${SRCDIR}/../third_party/tongsuo-install/lib

// Android arm64
#cgo android,arm64 LDFLAGS: -L${SRCDIR}/../third_party/tongsuo-install/android/arm64-v8a/lib -L${SRCDIR}/sm2keyexch/android/arm64-v8a -lcrypto -lssl -lkeyexchange

// Android arm (32-bit)
#cgo android,arm LDFLAGS: -L${SRCDIR}/../third_party/tongsuo-install/android/armeabi-v7a/lib -L${SRCDIR}/sm2keyexch/android/armeabi-v7a -lcrypto -lssl -lkeyexchange

// Android x86_64
#cgo android,amd64 LDFLAGS: -L${SRCDIR}/../third_party/tongsuo-install/android/x86_64/lib -L${SRCDIR}/sm2keyexch/android/x86_64 -lcrypto -lssl -lkeyexchange
*/
import "C"
