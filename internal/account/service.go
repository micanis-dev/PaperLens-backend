// Package account contains the account-lifecycle use cases that sit between
// HTTP authentication and a persistence implementation.
package account

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrNotFound       = errors.New("account not found")
	ErrAlreadyDeleted = errors.New("account is deleted")
)

type Deletion struct {
	RequestedAt time.Time `json:"requestedAt"`
	ExecuteAt   time.Time `json:"executeAt"`
}

// Store is deliberately small so the deletion policy is testable without a
// database. ProcessDue must atomically remove/anonymize server-owned data and
// mark the account unusable.
type Store interface {
	RequestDeletion(context.Context, string, time.Time, time.Time) (Deletion, error)
	CancelDeletion(context.Context, string) error
	Deletion(context.Context, string) (*Deletion, error)
	ProcessDue(context.Context, string, time.Time) (bool, error)
	ProcessAllDue(context.Context, time.Time) (int, error)
	IsActive(context.Context, string) (bool, error)
}

type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}
}

func (s *Service) RequestDeletion(ctx context.Context, userID string) (Deletion, error) {
	if s == nil || s.store == nil {
		return Deletion{}, ErrNotFound
	}
	now := s.now().UTC()
	return s.store.RequestDeletion(ctx, userID, now, now.Add(24*time.Hour))
}

func (s *Service) CancelDeletion(ctx context.Context, userID string) error {
	if s == nil || s.store == nil {
		return ErrNotFound
	}
	return s.store.CancelDeletion(ctx, userID)
}

func (s *Service) Deletion(ctx context.Context, userID string) (*Deletion, error) {
	if s == nil || s.store == nil {
		return nil, ErrNotFound
	}
	return s.store.Deletion(ctx, userID)
}

func (s *Service) ProcessDue(ctx context.Context, userID string) (bool, error) {
	if s == nil || s.store == nil {
		return false, nil
	}
	return s.store.ProcessDue(ctx, userID, s.now().UTC())
}

func (s *Service) IsActive(ctx context.Context, userID string) (bool, error) {
	if s == nil || s.store == nil {
		return true, nil
	}
	return s.store.IsActive(ctx, userID)
}

func (s *Service) ProcessDueAccounts(ctx context.Context) (int, error) {
	if s == nil || s.store == nil {
		return 0, nil
	}
	return s.store.ProcessAllDue(ctx, s.now().UTC())
}

// MemoryStore is used by local development and tests. Server-owned records
// are represented only by the active/deleted state here; a durable store must
// remove or anonymize the corresponding rows in one transaction.
type MemoryStore struct {
	mu      sync.Mutex
	active  map[string]bool
	pending map[string]Deletion
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{active: make(map[string]bool), pending: make(map[string]Deletion)}
}

func (s *MemoryStore) ensure(userID string) bool {
	active, exists := s.active[userID]
	if !exists {
		s.active[userID] = true
		return true
	}
	return active
}

func (s *MemoryStore) RequestDeletion(_ context.Context, userID string, requestedAt, executeAt time.Time) (Deletion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ensure(userID) {
		return Deletion{}, ErrAlreadyDeleted
	}
	if existing, ok := s.pending[userID]; ok {
		return existing, nil
	}
	deletion := Deletion{RequestedAt: requestedAt, ExecuteAt: executeAt}
	s.pending[userID] = deletion
	return deletion, nil
}

func (s *MemoryStore) CancelDeletion(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ensure(userID) {
		return ErrAlreadyDeleted
	}
	delete(s.pending, userID)
	return nil
}

func (s *MemoryStore) Deletion(_ context.Context, userID string) (*Deletion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ensure(userID) {
		return nil, ErrAlreadyDeleted
	}
	deletion, ok := s.pending[userID]
	if !ok {
		return nil, nil
	}
	return &deletion, nil
}

func (s *MemoryStore) ProcessDue(_ context.Context, userID string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ensure(userID) {
		return true, nil
	}
	deletion, ok := s.pending[userID]
	if !ok || now.Before(deletion.ExecuteAt) {
		return false, nil
	}
	s.active[userID] = false
	delete(s.pending, userID)
	return true, nil
}

func (s *MemoryStore) IsActive(_ context.Context, userID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ensure(userID), nil
}

func (s *MemoryStore) ProcessAllDue(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for userID, deletion := range s.pending {
		if now.Before(deletion.ExecuteAt) {
			continue
		}
		if s.active[userID] {
			s.active[userID] = false
			count++
		}
		delete(s.pending, userID)
	}
	return count, nil
}
