package main

import "math"

func mean(xs []float64) float64 {
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

func variance(xs []float64) float64 {
	m := mean(xs)

	var sum float64
	for _, x := range xs {
		dx := x - m
		sum += dx * dx
	}
	return sum / float64(len(xs))
}

func standardDeviation(xs []float64) float64 {
	return math.Sqrt(variance(xs))
}
