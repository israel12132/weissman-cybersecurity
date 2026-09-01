//! Structural SQL AST gate for compiled weissman_ro QueryPlans.
//!
//! Identifier / needle filters are not enough: JSON `\u003b` round-trips to `;`
//! after serde, and `chr()||chr()` never contains `--`. This module parses the
//! **compiled** parameterised SQL with `sqlparser` (PostgreSQL dialect) and
//! walks the tree. Only a SELECT whose tables/columns sit on the static
//! weissman_ro allow-list is admitted. Functions, concatenation, subqueries,
//! unions, and non-SELECT statements are rejected before the RO pool.

use crate::nl_query::{is_allowlisted_column, is_allowlisted_table};
use sqlparser::ast::{
    BinaryOperator, Expr, Function, GroupByExpr, Query, Select, SelectItem, SetExpr, Statement,
    TableFactor, TableWithJoins, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// Hard cap injected into the AST before weissman_ro execution. Never trust the LLM LIMIT.
pub const AST_STRICT_LIMIT: u64 = 200;

pub fn validate_compiled_sql_ast(sql: &str) -> Result<(), String> {
    validate_and_bound_sql(sql).map(|_| ())
}

/// Parse, inject/clamp `LIMIT 200`, walk the tree, return the rewritten SQL.
pub fn validate_and_bound_sql(sql: &str) -> Result<String, String> {
    let dialect = PostgreSqlDialect {};
    let ast = Parser::parse_sql(&dialect, sql).map_err(|e| format!("sql ast parse failed: {e}"))?;
    if ast.len() != 1 {
        return Err("sql ast: exactly one statement is required".into());
    }
    let mut stmt = ast
        .into_iter()
        .next()
        .ok_or_else(|| "sql ast: empty parse".to_string())?;
    inject_strict_limit_to_ast(&mut stmt);
    match &stmt {
        Statement::Query(q) => validate_query(q, true)?,
        other => {
            return Err(format!(
                "sql ast: only SELECT is permitted, got {}",
                statement_kind(other)
            ))
        }
    }
    Ok(stmt.to_string())
}

/// Physically inject `LIMIT 200` when missing or greater than [`AST_STRICT_LIMIT`].
pub fn inject_strict_limit_to_ast(statement: &mut Statement) {
    if let Statement::Query(query) = statement {
        inject_limit_on_query(query);
    }
}

fn inject_limit_on_query(query: &mut Query) {
    let needs_limit_override = match &query.limit {
        Some(Expr::Value(Value::Number(n, _))) => n
            .parse::<u64>()
            .map(|v| v > AST_STRICT_LIMIT)
            .unwrap_or(true),
        None => true,
        _ => true,
    };
    if needs_limit_override {
        query.limit = Some(Expr::Value(Value::Number(
            AST_STRICT_LIMIT.to_string(),
            false,
        )));
    }
}

fn statement_kind(s: &Statement) -> &'static str {
    match s {
        Statement::Query(_) => "query",
        Statement::Insert { .. } => "insert",
        Statement::Update { .. } => "update",
        Statement::Delete { .. } => "delete",
        Statement::CreateTable { .. } => "create_table",
        Statement::Copy { .. } => "copy",
        Statement::Execute { .. } => "execute",
        Statement::SetVariable { .. } => "set",
        _ => "other",
    }
}

fn validate_query(q: &Query, top_level: bool) -> Result<(), String> {
    if q.with.is_some() {
        return Err("sql ast: WITH/CTE is not permitted".into());
    }
    if !q.limit_by.is_empty()
        || q.offset.is_some()
        || q.fetch.is_some()
        || !q.locks.is_empty()
        || q.for_clause.is_some()
        || q.settings.is_some()
        || q.format_clause.is_some()
    {
        return Err("sql ast: LIMIT BY/OFFSET/FETCH/LOCK/FOR/SETTINGS are not permitted".into());
    }
    let table = match q.body.as_ref() {
        SetExpr::Select(sel) => validate_select(sel)?,
        SetExpr::Query(_) => return Err("sql ast: nested query body is not permitted".into()),
        SetExpr::SetOperation { .. } => {
            return Err("sql ast: UNION/EXCEPT/INTERSECT is not permitted".into())
        }
        SetExpr::Values(_) => return Err("sql ast: VALUES is not permitted".into()),
        SetExpr::Insert(_) => return Err("sql ast: INSERT body is not permitted".into()),
        SetExpr::Update(_) => return Err("sql ast: UPDATE body is not permitted".into()),
        SetExpr::Table(_) => return Err("sql ast: TABLE body is not permitted".into()),
    };
    if let Some(ob) = &q.order_by {
        if ob.interpolate.is_some() {
            return Err("sql ast: ORDER BY INTERPOLATE is not permitted".into());
        }
        for item in &ob.exprs {
            validate_ident_or_value(&item.expr, &table)?;
        }
    }
    if let Some(lim) = &q.limit {
        validate_literal_or_placeholder(lim)?;
    } else if top_level {
        return Err("sql ast: LIMIT is required".into());
    }
    Ok(())
}

fn validate_select(sel: &Select) -> Result<String, String> {
    if sel.into.is_some() {
        return Err("sql ast: SELECT INTO is not permitted".into());
    }
    if sel.top.is_some() {
        return Err("sql ast: SELECT TOP is not permitted".into());
    }
    if sel.distinct.is_some() {
        return Err("sql ast: DISTINCT is not permitted".into());
    }
    if !sel.lateral_views.is_empty()
        || sel.prewhere.is_some()
        || !sel.cluster_by.is_empty()
        || !sel.distribute_by.is_empty()
        || !sel.sort_by.is_empty()
        || !sel.named_window.is_empty()
        || sel.qualify.is_some()
        || sel.connect_by.is_some()
        || sel.value_table_mode.is_some()
    {
        return Err("sql ast: dialect-specific SELECT clauses are not permitted".into());
    }
    if sel.from.len() != 1 {
        return Err("sql ast: exactly one FROM table is required".into());
    }
    let table = validate_from(&sel.from[0])?;
    if !is_allowlisted_table(&table) {
        return Err(format!(
            "sql ast: table '{table}' is not on the weissman_ro allow-list"
        ));
    }
    for item in &sel.projection {
        match item {
            SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => {
                validate_ident_or_value(e, &table)?;
            }
            _ => {
                return Err("sql ast: wildcard / non-identifier projection is not permitted".into())
            }
        }
    }
    if let Some(pred) = &sel.selection {
        validate_pred(pred, &table)?;
    }
    if sel.having.is_some() {
        return Err("sql ast: HAVING is not permitted".into());
    }
    match &sel.group_by {
        GroupByExpr::Expressions(exprs, _) if exprs.is_empty() => {}
        _ => return Err("sql ast: GROUP BY is not permitted".into()),
    }
    Ok(table)
}

fn validate_from(tw: &TableWithJoins) -> Result<String, String> {
    if !tw.joins.is_empty() {
        return Err("sql ast: JOIN is not permitted".into());
    }
    match &tw.relation {
        TableFactor::Table {
            name,
            args,
            with_hints,
            version,
            partitions,
            json_path,
            with_ordinality,
            ..
        } => {
            if args.is_some()
                || !with_hints.is_empty()
                || version.is_some()
                || !partitions.is_empty()
                || json_path.is_some()
                || *with_ordinality
            {
                return Err("sql ast: table function / hints are not permitted".into());
            }
            object_name_unqualified(name)
        }
        TableFactor::Derived { .. } => {
            Err("sql ast: derived FROM subquery is not permitted".into())
        }
        TableFactor::TableFunction { .. } | TableFactor::Function { .. } => {
            Err("sql ast: table function is not permitted".into())
        }
        TableFactor::UNNEST { .. } => Err("sql ast: UNNEST is not permitted".into()),
        TableFactor::JsonTable { .. } | TableFactor::OpenJsonTable { .. } => {
            Err("sql ast: JSON_TABLE is not permitted".into())
        }
        TableFactor::NestedJoin { .. } => Err("sql ast: nested join is not permitted".into()),
        TableFactor::Pivot { .. } => Err("sql ast: PIVOT is not permitted".into()),
        TableFactor::Unpivot { .. } => Err("sql ast: UNPIVOT is not permitted".into()),
        TableFactor::MatchRecognize { .. } => {
            Err("sql ast: MATCH_RECOGNIZE is not permitted".into())
        }
    }
}

fn object_name_unqualified(name: &sqlparser::ast::ObjectName) -> Result<String, String> {
    let idents: Vec<String> = name
        .0
        .iter()
        .map(|i| i.value.to_ascii_lowercase())
        .collect();
    if idents.len() != 1 {
        return Err(format!(
            "sql ast: schema-qualified names are not permitted ({})",
            idents.join(".")
        ));
    }
    let t = idents.into_iter().next().unwrap();
    if t.starts_with("pg_") || t == "information_schema" {
        return Err(format!("sql ast: catalog table '{t}' is blocked"));
    }
    Ok(t)
}

fn column_ok(table: &str, col: &str) -> bool {
    // compile_plan injects tenant_id on tenant-scoped tables; it is not an LLM identifier.
    col == "tenant_id" || is_allowlisted_column(table, col)
}

fn validate_ident_or_value(e: &Expr, table: &str) -> Result<(), String> {
    match e {
        Expr::Identifier(id) => {
            let c = id.value.to_ascii_lowercase();
            if !column_ok(table, &c) {
                return Err(format!(
                    "sql ast: column '{c}' is not allow-listed on {table}"
                ));
            }
            Ok(())
        }
        Expr::CompoundIdentifier(parts) => {
            let c = parts
                .last()
                .map(|i| i.value.to_ascii_lowercase())
                .unwrap_or_default();
            if !column_ok(table, &c) {
                return Err(format!(
                    "sql ast: column '{c}' is not allow-listed on {table}"
                ));
            }
            Ok(())
        }
        Expr::Value(_) => Ok(()),
        Expr::Nested(inner) => validate_ident_or_value(inner, table),
        _ => Err("sql ast: projection must be an allow-listed identifier".into()),
    }
}

fn validate_literal_or_placeholder(e: &Expr) -> Result<(), String> {
    match e {
        Expr::Value(_) | Expr::Identifier(_) => Ok(()),
        Expr::Nested(inner) => validate_literal_or_placeholder(inner),
        _ => Err("sql ast: LIMIT must be a literal".into()),
    }
}

fn validate_pred(e: &Expr, table: &str) -> Result<(), String> {
    match e {
        Expr::Nested(inner) => validate_pred(inner, table),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => validate_ident_or_value(e, table),
        Expr::Value(_) => Ok(()),
        Expr::IsNull(inner) | Expr::IsNotNull(inner) => validate_pred(inner, table),
        Expr::InList { expr, list, .. } => {
            validate_pred(expr, table)?;
            for v in list {
                validate_pred(v, table)?;
            }
            Ok(())
        }
        Expr::Like { expr, pattern, .. }
        | Expr::ILike { expr, pattern, .. }
        | Expr::SimilarTo { expr, pattern, .. } => {
            validate_pred(expr, table)?;
            validate_pred(pattern, table)
        }
        Expr::BinaryOp { left, op, right } => {
            allow_predicate_op(op)?;
            validate_pred(left, table)?;
            validate_pred(right, table)
        }
        Expr::UnaryOp { expr, .. } => validate_pred(expr, table),
        Expr::Function(f) => Err(format!(
            "sql ast: function '{}' is not permitted",
            function_name(f)
        )),
        Expr::Subquery(_) | Expr::Exists { .. } | Expr::InSubquery { .. } => {
            Err("sql ast: subquery is not permitted".into())
        }
        Expr::Case { .. } => Err("sql ast: CASE is not permitted".into()),
        Expr::Cast { .. } => Err("sql ast: CAST is not permitted".into()),
        _ => Err("sql ast: unsupported predicate expression".into()),
    }
}

fn allow_predicate_op(op: &BinaryOperator) -> Result<(), String> {
    match op {
        BinaryOperator::Eq
        | BinaryOperator::NotEq
        | BinaryOperator::Lt
        | BinaryOperator::LtEq
        | BinaryOperator::Gt
        | BinaryOperator::GtEq
        | BinaryOperator::And
        | BinaryOperator::Or => Ok(()),
        BinaryOperator::StringConcat => {
            Err("sql ast: string concatenation is not permitted".into())
        }
        BinaryOperator::Custom(s) if s == "||" => {
            Err("sql ast: string concatenation is not permitted".into())
        }
        BinaryOperator::PGCustomBinaryOperator(parts)
            if parts
                .iter()
                .any(|p| p.contains("||") || p.eq_ignore_ascii_case("concat")) =>
        {
            Err("sql ast: concatenation operator is not permitted".into())
        }
        other => Err(format!("sql ast: operator '{other}' is not permitted")),
    }
}

fn function_name(f: &Function) -> String {
    f.name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nl_query::{compile_plan, QueryPlan};

    #[test]
    fn compiled_graph_select_passes_ast() {
        let qp = QueryPlan {
            table: "risk_graph_nodes".into(),
            select: vec!["id".into(), "label".into()],
            filters: vec![],
            order_by: Some("id".into()),
            order_desc: false,
            limit: Some(10),
            ..QueryPlan::default()
        };
        let compiled = compile_plan(&qp, 1).expect("compile");
        validate_compiled_sql_ast(&compiled.sql).expect("ast");
    }

    #[test]
    fn unicode_semicolon_is_not_a_valid_table() {
        // serde JSON `\u003b` becomes `;` before we ever compile. The AST gate
        // still rejects multi-statement / catalog SQL if it reached this layer.
        assert!(validate_compiled_sql_ast("SELECT id FROM risk_graph_nodes; SELECT 1").is_err());
    }

    #[test]
    fn weissman_ro_allowlist_excludes_users() {
        let names = crate::nl_query::allowlisted_table_names();
        assert!(names.contains(&"risk_graph_nodes"));
        assert!(names.contains(&"vulnerabilities"));
        assert!(!names.contains(&"users"));
        assert!(!names.contains(&"pg_shadow"));
        assert_eq!(names.len(), 17);
    }

    #[test]
    fn function_and_concat_blocked() {
        assert!(
            validate_compiled_sql_ast("SELECT pg_sleep(1) FROM risk_graph_nodes LIMIT 1").is_err()
        );
        assert!(validate_compiled_sql_ast(
            "SELECT chr(115)||chr(101) FROM risk_graph_nodes LIMIT 1"
        )
        .is_err());
        assert!(validate_compiled_sql_ast("SELECT id FROM pg_shadow LIMIT 1").is_err());
        assert!(validate_compiled_sql_ast("SELECT id FROM users LIMIT 1").is_err());
        assert!(validate_compiled_sql_ast(
            "SELECT id FROM risk_graph_nodes UNION SELECT id FROM users"
        )
        .is_err());
        assert!(validate_compiled_sql_ast("INSERT INTO risk_graph_nodes (id) VALUES (1)").is_err());
        assert!(validate_compiled_sql_ast(
            "SELECT id FROM risk_graph_nodes WHERE label = (SELECT passwd FROM pg_shadow) LIMIT 1"
        )
        .is_err());
    }

    fn sql_upper(s: &str) -> String {
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_uppercase()
    }

    #[test]
    fn injects_limit_200_when_missing() {
        let out = validate_and_bound_sql("SELECT id FROM risk_graph_nodes").expect("bound");
        assert!(
            sql_upper(&out).contains("LIMIT 200"),
            "expected LIMIT 200 in {out}"
        );
        validate_compiled_sql_ast(&out).expect("rewritten still valid");
    }

    #[test]
    fn clamps_limit_above_200() {
        let out =
            validate_and_bound_sql("SELECT id FROM risk_graph_nodes LIMIT 9999").expect("bound");
        let u = sql_upper(&out);
        assert!(u.contains("LIMIT 200"), "expected clamp in {out}");
        assert!(!u.contains("9999"), "stale limit survived in {out}");
    }

    #[test]
    fn preserves_limit_at_or_below_200() {
        let out =
            validate_and_bound_sql("SELECT id FROM risk_graph_nodes LIMIT 10").expect("bound");
        let u = sql_upper(&out);
        assert!(u.contains("LIMIT 10"), "expected LIMIT 10 in {out}");
        assert!(
            !u.contains("LIMIT 200"),
            "must not raise a small limit: {out}"
        );
    }
}
