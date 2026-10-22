package platform

import (
	"os"
	"path/filepath"
	"strings"
)

func (r *Runtime) xrayIdentity(fullDevice bool) (string, error) {
	if embeddedXrayAllowed(fullDevice) {
		return os.Executable()
	}
	return r.xrayPath(), nil
}

// WFP must permit the process which actually owns the endpoint sockets.
// Paths come from the running executable and fixed engine directory only.
func (r *Runtime) transportProcesses(kind int, fullDevice, needsXray bool) ([]string, error) {
	engine := r.enginePath(kind)
	if (kind < 2 && embeddedAWGEnabled()) || (kind >= 2 && embeddedSingBoxAllowed(fullDevice, false)) {
		var err error
		engine, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	paths := []string{filepath.Clean(engine)}
	if needsXray {
		identity, err := r.xrayIdentity(fullDevice)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(paths[0], filepath.Clean(identity)) {
			paths = append(paths, filepath.Clean(identity))
		}
	}
	return paths, nil
}
