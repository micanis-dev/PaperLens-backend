package account

import (
	"context"
	"testing"
	"time"
)

func TestDeletionCanBeCanceledDuringGracePeriod(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	service := NewService(store, func() time.Time { return now })
	deletion, err := service.RequestDeletion(context.Background(), "user_1")
	if err != nil || !deletion.ExecuteAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("deletion=%+v err=%v", deletion, err)
	}
	second, err := service.RequestDeletion(context.Background(), "user_1")
	if err != nil || !second.ExecuteAt.Equal(deletion.ExecuteAt) {
		t.Fatalf("repeated request extended grace: first=%+v second=%+v err=%v", deletion, second, err)
	}
	if err := service.CancelDeletion(context.Background(), "user_1"); err != nil {
		t.Fatal(err)
	}
	if pending, err := service.Deletion(context.Background(), "user_1"); err != nil || pending != nil {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
}

func TestDueDeletionMakesAccountInactive(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	service := NewService(store, func() time.Time { return now })
	if _, err := service.RequestDeletion(context.Background(), "user_1"); err != nil {
		t.Fatal(err)
	}
	deleted, err := store.ProcessDue(context.Background(), "user_1", now.Add(24*time.Hour))
	if err != nil || !deleted {
		t.Fatalf("deleted=%t err=%v", deleted, err)
	}
	active, err := service.IsActive(context.Background(), "user_1")
	if err != nil || active {
		t.Fatalf("active=%t err=%v", active, err)
	}
	if _, err := service.RequestDeletion(context.Background(), "user_1"); err != ErrAlreadyDeleted {
		t.Fatalf("request after deletion err=%v", err)
	}
}
