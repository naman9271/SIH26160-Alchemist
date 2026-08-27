package capture

import "os"

func removeTemporaryFile(path string) error { return os.Remove(path) }
