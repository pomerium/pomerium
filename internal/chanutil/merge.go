package chanutil

// Merge merges multiple channels together.
func Merge[T any](ins ...<-chan T) <-chan T {
	switch len(ins) {
	case 0:
		return nil
	case 1:
		return ins[0]
	case 2:
	default:
		return Merge(
			Merge(ins[:len(ins)/2]...),
			Merge(ins[len(ins)/2:]...),
		)
	}

	in1, in2 := ins[0], ins[1]
	out := make(chan T)
	go func() {
		for {
			if in1 == nil && in2 == nil {
				close(out)
				return
			}

			select {
			case item, ok := <-in1:
				if !ok {
					in1 = nil
					continue
				}

				out <- item
			case item, ok := <-in2:
				if !ok {
					in2 = nil
					continue
				}

				out <- item
			}
		}
	}()
	return out
}
