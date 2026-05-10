package vomc

import "testing"

func TestWilsonInterval(t *testing.T) {
	lo, hi := wilsonInterval(5, 10, 0.95)
	if lo < 0.23 || lo > 0.24 || hi < 0.76 || hi > 0.77 {
		t.Fatalf("interval = [%f, %f], want approximately [0.237, 0.763]", lo, hi)
	}
}

func TestWilsonIntervalEmptyTotal(t *testing.T) {
	lo, hi := wilsonInterval(0, 0, 0.95)
	if lo != 0 || hi != 1 {
		t.Fatalf("interval = [%f, %f], want [0, 1]", lo, hi)
	}
}
