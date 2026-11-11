//go:build !windows

package radar

type Tracker struct{}

func NewTracker(onNewServer func(hit EndpointHit), onGameToggle func(running bool)) *Tracker {
	return &Tracker{}
}
func (t *Tracker) SetTargetProcesses(names []string, excludeEndpointIP string) {}
func (t *Tracker) Start()                                                      {}
func (t *Tracker) Stop()                                                       {}
func (t *Tracker) ActiveUDPInPrefixes(prefixes []string, withinSec int64) bool { return false }
func (t *Tracker) Snapshot() Snapshot                                          { return Snapshot{} }
