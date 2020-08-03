package sqlstore

import (
	"bytes"
)

type SqlBuilder struct {
	sql    bytes.Buffer
	params []interface{}
}

func (sb *SqlBuilder) Write(sql string, params ...interface{}) {
	sb.sql.WriteString(sql)

	if len(params) > 0 {
		sb.params = append(sb.params, params...)
	}
}

func (sb *SqlBuilder) GetSqlString() string {
	return sb.sql.String()
}

func (sb *SqlBuilder) AddParams(params ...interface{}) {
	sb.params = append(sb.params, params...)
}
