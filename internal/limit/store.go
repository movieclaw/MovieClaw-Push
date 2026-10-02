package limit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 的 SQLite，镜像里不需要 C 库
)

// Store 是按「实例 × 天」汇总的计数在本地 SQLite 里的存放。中继没有数据库，
// 这是它唯一落盘的业务数据，只有数字。
type Store struct {
	db *sql.DB
}

const schema = `CREATE TABLE IF NOT EXISTS usage (
	instance     TEXT    NOT NULL,
	day          TEXT    NOT NULL,
	count        INTEGER NOT NULL,
	type         TEXT    NOT NULL,
	priority     TEXT    NOT NULL,
	interruption TEXT    NOT NULL,
	failures     TEXT    NOT NULL,
	hours        TEXT    NOT NULL,
	devices      BLOB    NOT NULL,
	updated_at   INTEGER NOT NULL,
	PRIMARY KEY (instance, day)
)`

// OpenStore 打开（必要时创建）计数文件。readOnly 给管理命令用，可以和运行中的中继同时打开。
func OpenStore(path string, readOnly bool) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	if readOnly {
		dsn = "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开计数文件 %s 失败：%w", path, err)
	}
	db.SetMaxOpenConns(1)
	if !readOnly {
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, fmt.Errorf("初始化计数文件 %s 失败：%w", path, err)
		}
	} else if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("打开计数文件 %s 失败：%w", path, err)
	}
	return &Store{db: db}, nil
}

// Close 关闭计数文件。
func (s *Store) Close() error { return s.db.Close() }

// Upsert 写入（覆盖）一批汇总。
func (s *Store) Upsert(list []*Stats) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO usage
		(instance, day, count, type, priority, interruption, failures, hours, devices, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (instance, day) DO UPDATE SET
			count = excluded.count, type = excluded.type, priority = excluded.priority,
			interruption = excluded.interruption, failures = excluded.failures,
			hours = excluded.hours, devices = excluded.devices, updated_at = excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for _, st := range list {
		_, err := stmt.Exec(st.Instance, st.Day, st.Count,
			mustJSON(st.Type), mustJSON(st.Priority), mustJSON(st.Interruption),
			mustJSON(st.Failures), mustJSON(st.Hours), st.Devices[:], now)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadDay 读出某一天的全部汇总。
func (s *Store) LoadDay(day string) ([]*Stats, error) {
	return s.query(`WHERE day = ?`, day)
}

// Since 返回从 since（含）起的汇总，按天、实例排序。
func (s *Store) Since(since string) ([]DayUsage, error) {
	list, err := s.query(`WHERE day >= ? ORDER BY day, instance`, since)
	if err != nil {
		return nil, err
	}
	out := make([]DayUsage, 0, len(list))
	for _, st := range list {
		out = append(out, st.usage())
	}
	return out, nil
}

// Prune 删除 before 之前的汇总。
func (s *Store) Prune(before string) error {
	_, err := s.db.Exec(`DELETE FROM usage WHERE day < ?`, before)
	return err
}

func (s *Store) query(where string, args ...any) ([]*Stats, error) {
	rows, err := s.db.Query(`SELECT instance, day, count, type, priority, interruption, failures, hours, devices
		FROM usage `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Stats
	for rows.Next() {
		st := newStats("", "")
		var typ, prio, intr, fail, hours string
		var devices []byte
		if err := rows.Scan(&st.Instance, &st.Day, &st.Count, &typ, &prio, &intr, &fail, &hours, &devices); err != nil {
			return nil, err
		}
		for _, f := range []struct {
			raw string
			dst any
		}{{typ, &st.Type}, {prio, &st.Priority}, {intr, &st.Interruption}, {fail, &st.Failures}, {hours, &st.Hours}} {
			if err := json.Unmarshal([]byte(f.raw), f.dst); err != nil {
				return nil, fmt.Errorf("计数文件里 %s/%s 的数据损坏：%w", st.Instance, st.Day, err)
			}
		}
		for _, m := range []*map[string]int64{&st.Type, &st.Priority, &st.Interruption, &st.Failures} {
			if *m == nil { // 存的是 null 时 Unmarshal 会把 map 置空，后面计数会写空 map
				*m = map[string]int64{}
			}
		}
		copy(st.Devices[:], devices)
		out = append(out, st)
	}
	return out, rows.Err()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // 只有 map[string]int64 和数组，不会失败
	}
	return string(b)
}
