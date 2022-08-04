package pollers

func NewLimiter(size int) *Limiter {
	return &Limiter{make(chan int, size)}
}

// Basic generic resource limiter.
type Limiter struct {
	throttle chan int
}

func (lim *Limiter) Lock() {
	lim.throttle <- 1
}

func (lim *Limiter) Unlock() {
	<-lim.throttle
}
