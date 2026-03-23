package missingcrypt

import "fmt"

// WrappedError pairs a human-readable message with an underlying error and an
// optional map of structured context values for programmatic inspection.
// ctx is unexported so it is only accessible within the package.
type WrappedError struct {
	Err error
	Msg string
	ctx map[string]any
}

func (we WrappedError) Error() string {
	if we.Msg == "" {
		if we.Err == nil {
			return ""
		}

		return we.Err.Error()
	}

	if we.Err == nil {
		return we.Msg
	}

	return fmt.Sprintf("%s: %v", we.Msg, we.Err)
}
