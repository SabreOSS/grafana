package permissions

import (
	"strings"

	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
)

type DashboardPermissionTable struct {
	OrgRole         models.RoleType
	Dialect         migrator.Dialect
	UserId          int64
	OrgId           int64
	PermissionLevel models.PermissionType
}

// returns table that maps dashboard ids to information about their visibilities based on permissions:
// viewable -> dashboard/folder's content is allowed to be visited (by url)
// listable -> dashboard/folder is allowed to be displayed on list
// folder_viewable -> in context of dashboard, its folder is allowed to be visited (by url) - field used when folders are not fetched separately
func (d DashboardPermissionTable) Table() (string, []interface{}) {
	falseStr := d.Dialect.BooleanStr(false)
	trueStr := d.Dialect.BooleanStr(true)
	okRoles := []interface{}{d.OrgRole}

	if d.OrgRole == models.ROLE_EDITOR {
		okRoles = append(okRoles, models.ROLE_VIEWER)
	} else if d.OrgRole == models.ROLE_ADMIN {
		return `(SELECT id AS d_id, 1 AS viewable, 1 as listable, 1 AS folder_viewable FROM dashboard)`, nil
	}

	sql := `(
			SELECT DashboardId as d_id, MAX(viewable) AS viewable, MAX(listable) as listable, MAX(folder_viewable) as folder_viewable FROM (
				SELECT d.id AS DashboardId, 1 as viewable, 1 as listable, CASE WHEN da.dashboard_id = d.folder_id THEN 1 ELSE 0 END as folder_viewable
					FROM dashboard AS d
					LEFT JOIN dashboard AS folder on folder.id = d.folder_id
					LEFT JOIN dashboard_acl AS da ON
						da.dashboard_id = d.id OR
						da.dashboard_id = d.folder_id
					LEFT JOIN team_member as ugm on ugm.team_id = da.team_id
					WHERE
						d.org_id = ? AND
						da.permission >= ? AND
						(
							da.user_id = ? OR
							ugm.user_id = ? OR
							da.role IN (?` + strings.Repeat(",?", len(okRoles)-1) + `)
						)
				-- include permissions from child dashboards -->
				UNION
				SELECT folder.id AS DashboardId, 0 as viewable, 1 as listable, 0 as folder_viewable
					FROM dashboard AS folder
					LEFT JOIN dashboard AS d on folder.id = d.folder_id
					LEFT JOIN dashboard_acl AS da ON
						da.dashboard_id = d.id
					LEFT JOIN team_member as ugm on ugm.team_id = da.team_id
					WHERE
						folder.is_folder = ` + trueStr + ` AND
						d.org_id = ? AND
						da.permission >= ? AND
						(
							da.user_id = ? OR
							ugm.user_id = ? OR
							da.role IN (?` + strings.Repeat(",?", len(okRoles)-1) + `)
						)
				UNION
				SELECT d.id AS DashboardId, 1 as viewable, 1 as listable, CASE WHEN folder.id = d.folder_id THEN 1 ELSE 0 END as folder_viewable
					FROM dashboard AS d
					LEFT JOIN dashboard AS folder on folder.id = d.folder_id
					LEFT JOIN dashboard_acl AS da ON
						(
							-- include default permissions -->
							da.org_id = -1 AND (
							  (folder.id IS NOT NULL AND folder.has_acl = ` + falseStr + `) OR
							  (folder.id IS NULL AND d.has_acl = ` + falseStr + `)
							)
						)
					WHERE
						d.org_id = ? AND
						da.permission >= ? AND
						(
							da.user_id = ? OR
							da.role IN (?` + strings.Repeat(",?", len(okRoles)-1) + `)
						)
			) AS a
			GROUP BY DashboardId
		)
	`

	params := []interface{}{d.OrgId, d.PermissionLevel, d.UserId, d.UserId}
	params = append(params, okRoles...)
	params = append(params, d.OrgId, d.PermissionLevel, d.UserId, d.UserId)
	params = append(params, okRoles...)
	params = append(params, d.OrgId, d.PermissionLevel, d.UserId)
	params = append(params, okRoles...)
	return sql, params
}
