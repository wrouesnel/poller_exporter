package pollers

func NewLimiter(size int) *Limiter {
	return &Limiter{ make(chan int, size) }
}

// Basic generic resource limiter
type Limiter struct {
	throttle chan int
}

func (this *Limiter) Lock() {
	this.throttle <- 1
}

func (this *Limiter) Unlock() {
	<- this.throttle
}