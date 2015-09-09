package pollers

import (

)

const Namespace = "poller"

// Implements the basic interface for updating pollers.
type Poller interface {
	Poll()	// Causes the service to update its internal state.
}

