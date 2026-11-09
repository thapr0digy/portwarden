package bad

func (s *Store) tx() { s.pool.Begin(nil) }

func (s *Store) SetX() { s.pool.Exec(nil, "UPDATE x SET y = 1") }

func (s *Store) Sneaky() { s.pool.QueryRow(nil, "INSERT INTO x VALUES (1) RETURNING id", 1) }

func (s *Store) Read() { s.pool.Query(nil, "SELECT id FROM x WHERE y = $1", 1) }
