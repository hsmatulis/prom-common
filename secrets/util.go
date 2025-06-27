package secrets

func count[T comparable](values ...T) int {
	count := 0
	var zero T
	for _, value := range values {
		if value != zero {
			count++
		}
	}
	return count
}
