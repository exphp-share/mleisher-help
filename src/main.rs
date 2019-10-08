//
// Simple program to analyze a history of MAC addresses showing up on switches
// and print out any that haven't appeared in at least 6 months.
//
// Mark Leisher <mleisher@cs.nmsu.edu>
// 07 October 2019
//
extern crate chrono;
extern crate regex;

use std::env;
use std::fs::File;
use std::io::*;
use std::process;
use regex::Regex;
use std::collections::HashMap;
use chrono::{DateTime, NaiveDateTime, Datelike, Local};

static NMONTHS: u32         = 6;
static VERBOSE: bool        = true;
static SWITCH_HISTORY: &str = "fakehistory.txt";
static DATABASE: &str       = "fakehosts.txt";

fn basename<'a>(path: &'a str, suff: &str) -> &'a str {
    let mut end: usize = path.len();
    if path.ends_with(suff) {
        end -= suff.len();
    }
    &path[..end]
}

struct Mac {
    dates: Vec<String>,
    count: u64,
}
impl Mac {
    pub fn new() -> Mac {
        Mac { dates: Vec::with_capacity(2), count: 1 }
    }
}

//
// Load all the MAC addresses with their first and last seen dates.
//
fn load_switch_history(prog: &str, emap: &mut HashMap<String, Mac>) {
    let re = Regex::new(r"^(\d+)_\d+\s+\S+\s+\S+\s+\S+\s+(([0-9A-F]+,?)+)").unwrap();
    //
    // Do the following as a block so the file will be closed.
    //
    {
        let infile = match File::open(SWITCH_HISTORY) {
            Err(_why) => {
                println!("{}: unable to open switchwalk history '{}': {}",
                         prog, SWITCH_HISTORY, _why);
                process::exit(1)
            },
            Ok(infile) => infile,
        };
        let reader = BufReader::new(infile);
        for line in reader.lines() {
            let l = line.unwrap();
            match re.captures(l.as_str()) {
                Some(x) => {
                    let date = x[1].to_owned();;
                    let mac = x[2].to_owned();
                    let e = emap.entry(mac).or_insert(Mac::new());
                    if e.dates.len() == 2 {
                        e.dates.pop();
                    }
                    e.dates.push(date);
                    e.count += 1;
                },
                None => (),
            };
        }
    }
}

//
// Function to determine the number of months between two dates.
//
fn nm(start: &str, end: Option<&str>, now: &DateTime<Local>) -> u32 {
    let ey: u32;
    let em: u32;
    let s = NaiveDateTime::parse_from_str(start, "%Y%m%d_%H%M%S").unwrap();

    if let Some(end) = end {
        let edt = NaiveDateTime::parse_from_str(end, "%Y%m%d_%H%M%S").unwrap();
        ey = edt.year() as u32;
        em = edt.month() as u32;
    } else {
        ey = now.year() as u32;
        em = now.month() as u32;
    }

    let sy = s.year() as u32;
    let sm = s.month() as u32;
    ((12 * (ey - sy)) + em - sm)
}

//
// Function to scan the database file for any hosts that haven't appeared in the
// switch history in the last NMONTHS (NMONTHS specified above).
//
fn scan_database(prog: &str, now: &DateTime<Local>, emap: &HashMap<String, Mac>) {
    let res: [Regex; 3] = [ Regex::new(r"^#").unwrap(),
                            Regex::new(r"^\s*$").unwrap(),
                            Regex::new(r"host13|host42").unwrap() ];
    //
    // Wrap in brackets to automatically close the file when it goes out of scope.
    //
    {
        let infile = match File::open(DATABASE) {
            Err(_why) => {
                println!("{}: unable to open host database '{}': {}", prog, DATABASE, _why);
                process::exit(1)
            },
            Ok(infile) => infile,
        };
        let reader = BufReader::new(infile);
        'outer: for (lno, line_result) in reader.lines().enumerate() {
            println!("Line: {}", lno + 1);
            let line = line_result.unwrap();
            for r in &res {
                if r.is_match(line.as_str()) {
                    continue 'outer;
                }
            }
            let l = line.as_str().split("%").
                enumerate().
                filter(|&(i,_)|  i == 0 || i == 1 || i == 8).
                map(|(_,f)| f);
            let fvec: Vec<&str> = l.collect();
            let ip   = fvec[0];
            let host = fvec[1];
            let mac = fvec[2].replace("-","").to_uppercase();
            match emap.get(&mac) {
                Some(v) => {
                    let n: u32;
                    if v.dates.len() == 1 {
                        n = nm(&v.dates[0], None, now);
                    } else {
                        n = nm(&v.dates[0], Some(&v.dates[1]), now);
                    }
                    if n >= NMONTHS {
                        println!("DING! {} {} {} Months: {}", ip, host, mac, n);
                    }
                },
                None => ()
            };
        }
    };
}

fn main() {
    let arg = env::args().next().unwrap();
    let prog = basename(&arg, "");
    let now: DateTime<Local> = Local::now();
    let mut emap: HashMap<String, Mac> = HashMap::new();

    if VERBOSE {
        eprint!("Loading switch history...");
    }
    load_switch_history(prog, &mut emap);
    if VERBOSE {
        eprintln!("done.");
        eprint!("Scanning database...");
    }
    scan_database(prog, &now, &emap);
    if VERBOSE {
        eprintln!("done.");
    }
}
