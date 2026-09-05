//! Thin bash-like AST for the debug-shell decoy. Uses `nom` to split `;`, `&&`,
//! `||`, and `|`. Nothing here execs a real process.

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, space0},
    combinator::{map, opt},
    multi::many0,
    sequence::{delimited, preceded},
    IResult,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnmatchedQuote(char),
    Syntax(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqOp {
    Seq,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub cmds: Vec<Command>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndOr {
    pub first: Pipeline,
    pub rest: Vec<(SeqOp, Pipeline)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub stmts: Vec<AndOr>,
}

pub fn parse_script(input: &str) -> Result<Script, ParseError> {
    if unmatched_quote(input).is_some() {
        return Err(ParseError::UnmatchedQuote(unmatched_quote(input).unwrap()));
    }
    match script(input.trim()) {
        Ok((rest, ast)) if rest.trim().is_empty() => {
            if ast.stmts.is_empty() {
                Ok(Script { stmts: vec![] })
            } else {
                Ok(ast)
            }
        }
        Ok((rest, _)) if rest.trim_start().starts_with('|') => {
            Err(ParseError::Syntax("syntax error near unexpected token `|'"))
        }
        Ok(_) => Err(ParseError::Syntax("syntax error")),
        Err(_) => Err(ParseError::Syntax("syntax error")),
    }
}

fn unmatched_quote(s: &str) -> Option<char> {
    let mut q: Option<char> = None;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            chars.next();
            continue;
        }
        match q {
            None if c == '\'' || c == '"' => q = Some(c),
            Some(qq) if c == qq => q = None,
            _ => {}
        }
    }
    q
}

fn is_op_start(c: char) -> bool {
    matches!(c, ';' | '&' | '|')
}

fn word_char(c: char) -> bool {
    !c.is_whitespace() && !is_op_start(c) && c != '\'' && c != '"'
}

fn single_quoted(i: &str) -> IResult<&str, String> {
    delimited(
        char('\''),
        map(opt(take_while1(|c| c != '\'')), |s| {
            s.unwrap_or("").to_string()
        }),
        char('\''),
    )(i)
}

fn double_quoted(i: &str) -> IResult<&str, String> {
    delimited(
        char('"'),
        map(opt(take_while1(|c| c != '"')), |s| {
            s.unwrap_or("").to_string()
        }),
        char('"'),
    )(i)
}

fn bare_word(i: &str) -> IResult<&str, String> {
    map(take_while1(word_char), |s: &str| s.to_string())(i)
}

fn token(i: &str) -> IResult<&str, String> {
    preceded(space0, alt((single_quoted, double_quoted, bare_word)))(i)
}

fn command(i: &str) -> IResult<&str, Command> {
    let (i, first) = token(i)?;
    let (i, rest) = many0(token)(i)?;
    let mut argv = vec![first];
    argv.extend(rest);
    // Drop redirections so `cmd 2>/dev/null` still looks like bash, not "command not found".
    let argv: Vec<String> = argv
        .into_iter()
        .filter(|a| !a.starts_with('>') && !a.starts_with("2>") && !a.starts_with("1>") && a != "&")
        .collect();
    Ok((i, Command { argv }))
}

fn pipeline(i: &str) -> IResult<&str, Pipeline> {
    let (i, first) = command(i)?;
    let (i, rest) = many0(preceded(delimited(space0, tag("|"), space0), command))(i)?;
    let mut cmds = vec![first];
    cmds.extend(rest);
    Ok((i, Pipeline { cmds }))
}

fn seq_op(i: &str) -> IResult<&str, SeqOp> {
    preceded(
        space0,
        alt((
            map(tag("&&"), |_| SeqOp::And),
            map(tag("||"), |_| SeqOp::Or),
            map(tag(";"), |_| SeqOp::Seq),
        )),
    )(i)
}

fn and_or(i: &str) -> IResult<&str, AndOr> {
    let (i, first) = pipeline(i)?;
    let (mut i, mut rest) = (i, Vec::new());
    loop {
        match seq_op(i) {
            Ok((n, op)) => match pipeline(n) {
                Ok((n2, p)) => {
                    rest.push((op, p));
                    i = n2;
                }
                Err(_) if op == SeqOp::Seq => {
                    i = n;
                    break;
                }
                Err(e) => return Err(e),
            },
            Err(_) => break,
        }
    }
    Ok((i, AndOr { first, rest }))
}

fn script(i: &str) -> IResult<&str, Script> {
    let (i, _) = space0(i)?;
    if i.is_empty() {
        return Ok((i, Script { stmts: vec![] }));
    }
    let (i, first) = and_or(i)?;
    Ok((i, Script { stmts: vec![first] }))
}

/// Human-readable bash-shaped parse failure.
pub fn parse_error_text(err: &ParseError) -> String {
    match err {
        ParseError::UnmatchedQuote(q) => {
            format!("bash: unexpected EOF while looking for matching `{q}'\n")
        }
        ParseError::Syntax(s) => format!("bash: {s}\n"),
    }
}

/// Walk AST left-to-right. `run_cmd` never executes a host binary.
pub fn eval_script<F>(script: &Script, mut run_cmd: F) -> (String, String, i32)
where
    F: FnMut(&Command, Option<&str>) -> (String, String, i32),
{
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit = 0;
    for stmt in &script.stmts {
        let (o, e, x) = eval_and_or(stmt, &mut run_cmd);
        stdout.push_str(&o);
        stderr.push_str(&e);
        exit = x;
    }
    (stdout, stderr, exit)
}

fn eval_and_or<F>(node: &AndOr, run_cmd: &mut F) -> (String, String, i32)
where
    F: FnMut(&Command, Option<&str>) -> (String, String, i32),
{
    let (mut out, mut err, mut exit) = eval_pipeline(&node.first, run_cmd);
    for (op, pipe) in &node.rest {
        match op {
            SeqOp::And if exit != 0 => continue,
            SeqOp::Or if exit == 0 => continue,
            _ => {}
        }
        let (o, e, x) = eval_pipeline(pipe, run_cmd);
        out.push_str(&o);
        err.push_str(&e);
        exit = x;
    }
    (out, err, exit)
}

fn eval_pipeline<F>(pipe: &Pipeline, run_cmd: &mut F) -> (String, String, i32)
where
    F: FnMut(&Command, Option<&str>) -> (String, String, i32),
{
    if pipe.cmds.len() == 1 {
        return run_cmd(&pipe.cmds[0], None);
    }
    let mut prev_stdout: Option<String> = None;
    let mut last_err = String::new();
    let mut last_exit = 0;
    let mut last_out = String::new();
    for cmd in &pipe.cmds {
        let stdin = prev_stdout.as_deref();
        let (o, e, x) = run_cmd(cmd, stdin);
        last_err.push_str(&e);
        last_exit = x;
        last_out = o.clone();
        prev_stdout = Some(o);
        if x == 127 {
            break;
        }
    }
    (last_out, last_err, last_exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_semicolon_and_and() {
        let s = parse_script("whoami; id").unwrap();
        assert_eq!(s.stmts[0].first.cmds[0].argv, vec!["whoami"]);
        assert_eq!(s.stmts[0].rest[0].0, SeqOp::Seq);
        assert_eq!(s.stmts[0].rest[0].1.cmds[0].argv, vec!["id"]);

        let s = parse_script("echo 'test' && uname -a").unwrap();
        assert_eq!(s.stmts[0].first.cmds[0].argv, vec!["echo", "test"]);
        assert_eq!(s.stmts[0].rest[0].0, SeqOp::And);
        assert_eq!(s.stmts[0].rest[0].1.cmds[0].argv, vec!["uname", "-a"]);
    }

    #[test]
    fn splits_pipe() {
        let s = parse_script("cat /etc/passwd | grep root").unwrap();
        assert_eq!(s.stmts[0].first.cmds.len(), 2);
        assert_eq!(s.stmts[0].first.cmds[1].argv, vec!["grep", "root"]);
    }

    #[test]
    fn unmatched_quote_is_bash_shaped() {
        let e = parse_script("echo 'oops").unwrap_err();
        let t = parse_error_text(&e);
        assert!(t.contains("unexpected EOF while looking for matching"));
        assert!(t.contains('\''));
    }

    #[test]
    fn empty_pipe_is_syntax_error() {
        let err = parse_script("cat |").unwrap_err();
        assert!(parse_error_text(&err).contains("syntax error"));
    }
}
