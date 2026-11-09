package good

func (s *Store) tx() { s.pool.Begin(nil) }

func (s *Store) Read() { s.pool.QueryRow(nil, "SELECT updated_at FROM x WHERE y = $1", 1) }
