package analysis

import "context"

// FusionRunID resolves every retained analysis, including previous workspaces.
func (s *Service) FusionRunID(ctx context.Context, id string) (string, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return "", err
	}
	return record.FusionRunID, nil
}
