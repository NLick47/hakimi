use anyhow::Result;
use serde::Serialize;

/// How a command renders its result.
///
/// `--json` is a global flag, so every command has exactly one machine format
/// and one human format, chosen in the same place for all of them.
#[derive(Clone, Copy)]
pub struct Output {
    json: bool,
}

impl Output {
    pub fn new(json: bool) -> Self {
        Self { json }
    }

    pub fn is_json(self) -> bool {
        self.json
    }

    pub fn json<T: Serialize>(self, value: &T) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(value)?);
        Ok(())
    }

    /// One `label: value` line, with the values aligned across a block.
    pub fn field(self, label: &str, value: impl std::fmt::Display) {
        println!("{:<14}{value}", format!("{label}:"));
    }

    /// `right` lists the numeric columns, which are right-aligned.
    pub fn table(self, headers: &[&str], rows: &[Vec<String>], right: &[usize]) {
        let mut widths: Vec<usize> = headers.iter().map(|head| head.chars().count()).collect();
        for row in rows {
            for (index, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(index) {
                    *width = (*width).max(cell.chars().count());
                }
            }
        }
        let header: Vec<String> = headers.iter().map(|head| head.to_string()).collect();
        print_row(&header, &widths, right);
        for row in rows {
            print_row(row, &widths, right);
        }
    }
}

fn print_row(cells: &[String], widths: &[usize], right: &[usize]) {
    let mut line = String::new();
    for (index, width) in widths.iter().enumerate() {
        let cell = cells.get(index).map(String::as_str).unwrap_or("");
        if index > 0 {
            line.push_str("  ");
        }
        if right.contains(&index) {
            line.push_str(&format!("{cell:>width$}", width = *width));
        } else {
            line.push_str(&format!("{cell:<width$}", width = *width));
        }
    }
    println!("{}", line.trim_end());
}
