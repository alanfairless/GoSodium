package support

import "fmt"
//
// Internal support functions
//

// CheckSize verifies the expected size of an input or output byte array.
func CheckSize(buf []byte, expected int, descrip string) {
	if len(buf) != expected {
		panic(fmt.Sprintf("Incorrect %s buffer size, expected (%d), got (%d).", descrip, expected, len(buf)))
	}
}
